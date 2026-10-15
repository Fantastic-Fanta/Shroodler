"""JavaScript prototype-pollution probes (query params and JSON bodies)."""

from __future__ import annotations

import json
import secrets
from typing import Any

import httpx

from shroodler.extractors.challenge import detect_challenge
from shroodler.models import Finding
from shroodler.pacer import Pacer
from shroodler.probes.common import (
    body_text,
    dedupe,
    inject,
    normalize_params,
    request,
)


def _spurious_reflection(resp: Any, clean_body: str, nonce: str) -> bool:
    """True when a detected 'reflection' is not real application reflection.

    A WAF/bot-mitigation block page echoes the offending request, so its body
    contains the marker even though the app never reflected it (the common
    false positive behind a WAF). And if the marker is already in the clean
    baseline, its presence is not reflection either.
    """
    body = body_text(resp)
    try:
        headers = {str(k): str(v) for k, v in (getattr(resp, "headers", {}) or {}).items()}
    except Exception:  # noqa: BLE001
        headers = {}
    status = int(getattr(resp, "status_code", 0) or 0)
    if detect_challenge(headers, body, status) is not None:
        return True
    return bool(nonce) and nonce in (clean_body or "")

QUERY_PAYLOADS = (
    "__proto__[shroodlerPP]={nonce}",
    "constructor[prototype][shroodlerPP]={nonce}",
    "__proto__.shroodlerPP={nonce}",
)
JSON_PAYLOADS = (
    {"__proto__": {"shroodlerPP": "{nonce}"}},
    {"constructor": {"prototype": {"shroodlerPP": "{nonce}"}}},
)


def looks_like_api(url: str, content_type: str = "") -> bool:
    lowered = (url or "").lower()
    ctype = (content_type or "").lower()
    if "/api/" in lowered:
        return True
    if "application/json" in ctype or ctype.endswith("+json"):
        return True
    return False


def _contains_pp(value, nonce: str) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key) == "shroodlerPP" and str(item) == nonce:
                return True
            if _contains_pp(item, nonce):
                return True
        return False
    if isinstance(value, list):
        return any(_contains_pp(item, nonce) for item in value)
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (json.JSONDecodeError, TypeError, ValueError):
            return '"shroodlerPP"' in value and nonce in value
        return _contains_pp(parsed, nonce)
    return False


def _parse_json(text: str):
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        return None


def _status(resp: httpx.Response | None) -> int:
    if resp is None:
        return 0
    try:
        return int(getattr(resp, "status_code", 0) or 0)
    except (TypeError, ValueError):
        return 0


def _json_request(
    url: str,
    method: str,
    payload: dict,
    cookie_header: str,
    *,
    client: httpx.Client | None,
    pacer: Pacer | None,
) -> httpx.Response | None:
    return request(
        method,
        url,
        cookie_header=cookie_header,
        extra_headers={"Content-Type": "application/json", "Accept": "application/json"},
        client=client,
        pacer=pacer,
        json=payload,
    )


def probe_prototype_pollution(
    url: str,
    method: str,
    params: list[dict],
    cookie_header: str,
    *,
    content_type: str = "",
    client: httpx.Client | None = None,
    pacer: Pacer | None = None,
) -> list[Finding]:
    """Inject __proto__/constructor.prototype keys into API endpoints."""
    if not looks_like_api(url, content_type):
        return []
    method_u = (method or "GET").upper()
    if method_u not in {"GET", "POST", "PUT", "PATCH"}:
        return []

    findings: list[Finding] = []
    normalized = normalize_params(params)
    # 16 hex chars: long enough that it will not collide by chance inside a
    # large serialized response (a short nonce could).
    nonce = secrets.token_hex(8)
    key = "shroodlerPP"

    clean = request(
        method_u if method_u != "GET" else "GET",
        url,
        cookie_header=cookie_header,
        extra_headers={"Accept": "application/json"} if method_u != "GET" else None,
        client=client,
        pacer=pacer,
        json={} if method_u in {"POST", "PUT", "PATCH"} else None,
    )
    clean_status = _status(clean)
    clean_body = body_text(clean)

    def _record_reflected(evidence: str) -> None:
        findings.append(
            Finding(
                id="prototype-pollution-reflected",
                severity="low",
                category="payload",
                url=url,
                description=(
                    "The response echoed a prototype-pollution marker. Reflection is "
                    "not proof of pollution: confirm the injected property actually "
                    "leaks into an unrelated response/object (and that the backend is "
                    "a JS/Node runtime) before treating this as a real finding."
                ),
                evidence=evidence,
                confidence="heuristic",
            )
        )

    def _record_behavior(evidence: str) -> None:
        findings.append(
            Finding(
                id="prototype-pollution-behavior",
                severity="medium",
                category="payload",
                url=url,
                description=(
                    "A prototype-pollution payload changed the status from 200 to 500."
                ),
                evidence=evidence,
                confidence="heuristic",
            )
        )

    if method_u == "GET" or normalized:
        for item in normalized or [{"name": "q", "value": "", "in": "query"}]:
            name = item["name"]
            for template in QUERY_PAYLOADS:
                payload = template.format(nonce=nonce)
                resp = inject(
                    url,
                    "GET" if method_u == "GET" else method_u,
                    normalized or [{"name": name, "value": "", "in": "query"}],
                    name,
                    payload,
                    cookie_header=cookie_header,
                    client=client,
                    pacer=pacer,
                )
                body = body_text(resp)
                parsed = _parse_json(body)
                if (
                    (parsed is not None and _contains_pp(parsed, nonce))
                    or (key in body and nonce in body)
                ) and not _spurious_reflection(resp, clean_body, nonce):
                    _record_reflected(f"param={name} payload={payload} nonce={nonce}")
                elif clean_status == 200 and _status(resp) == 500:
                    _record_behavior(
                        f"param={name} payload={payload} clean=200 polluted=500 nonce={nonce}"
                    )

    if method_u in {"POST", "PUT", "PATCH"} or "application/json" in (
        content_type or ""
    ).lower():
        json_method = method_u if method_u != "GET" else "POST"
        for template in JSON_PAYLOADS:
            raw = json.dumps(template).replace("{nonce}", nonce)
            payload = json.loads(raw)
            resp = _json_request(
                url,
                json_method,
                payload,
                cookie_header,
                client=client,
                pacer=pacer,
            )
            body = body_text(resp)
            parsed = _parse_json(body)
            if (
                (parsed is not None and _contains_pp(parsed, nonce))
                or (key in body and nonce in body)
            ) and not _spurious_reflection(resp, clean_body, nonce):
                _record_reflected(f"json={raw} nonce={nonce}")
            elif clean_status == 200 and _status(resp) == 500:
                _record_behavior(f"json={raw} clean=200 polluted=500 nonce={nonce}")

            follow = request(
                json_method if json_method != "GET" else "GET",
                url,
                cookie_header=cookie_header,
                extra_headers={"Accept": "application/json"},
                client=client,
                pacer=pacer,
                json={} if json_method != "GET" else None,
            )
            follow_body = body_text(follow)
            follow_parsed = _parse_json(follow_body)
            persisted = (
                follow_parsed is not None and _contains_pp(follow_parsed, nonce)
            ) or (key in follow_body and nonce in follow_body and nonce not in clean_body)
            if persisted:
                findings.append(
                    Finding(
                        id="prototype-pollution-persistent",
                        severity="critical",
                        category="payload",
                        url=url,
                        description=(
                            "A subsequent clean request still reflected the pollution marker."
                        ),
                        evidence=f"nonce={nonce} json={raw}",
                        confidence="confirmed",
                    )
                )

    return dedupe(findings)
