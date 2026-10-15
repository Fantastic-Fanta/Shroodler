"""CRLF header injection and response-splitting probes."""

from __future__ import annotations

import secrets
from urllib.parse import urlparse, urlunparse

import httpx

from shroodler.models import Finding
from shroodler.pacer import Pacer
from shroodler.probes.common import (
    challenge_vendor,
    dedupe,
    inject,
    normalize_params,
    probe_challenge_finding,
    request,
)

_REDIRECT_HINTS = (
    "login",
    "signin",
    "sign-in",
    "redirect",
    "logout",
    "callback",
    "return",
    "next",
)
_HEADER_NAME = "x-injected"


def _header_value(resp: httpx.Response | None, name: str) -> str:
    if resp is None:
        return ""
    headers = getattr(resp, "headers", None) or {}
    try:
        value = headers.get(name)
        if value:
            return str(value)
        # httpx is case-insensitive; also scan items for concatenated headers
        for key, val in headers.items():
            if str(key).lower() == name.lower():
                return str(val)
    except Exception:  # noqa: BLE001
        return ""
    return ""


def _all_header_blob(resp: httpx.Response | None) -> str:
    if resp is None:
        return ""
    headers = getattr(resp, "headers", None) or {}
    try:
        parts = [f"{k}: {v}" for k, v in headers.items()]
        return "\n".join(parts)
    except Exception:  # noqa: BLE001
        return ""


def _set_cookie(resp: httpx.Response | None) -> str:
    if resp is None:
        return ""
    headers = getattr(resp, "headers", None) or {}
    try:
        raw = headers.get("set-cookie") or headers.get("Set-Cookie") or ""
        if isinstance(raw, (list, tuple)):
            return "\n".join(str(item) for item in raw)
        return str(raw)
    except Exception:  # noqa: BLE001
        return ""


def _looks_redirect(url: str) -> bool:
    lowered = (url or "").lower()
    return any(hint in lowered for hint in _REDIRECT_HINTS)


def _path_with_crlf(url: str, suffix: str) -> str:
    parsed = urlparse(url)
    path = parsed.path or "/"
    return urlunparse(parsed._replace(path=path + suffix, query=""))


def probe_crlf(
    url: str,
    method: str,
    params: list[dict],
    cookie_header: str,
    *,
    client: httpx.Client | None = None,
    pacer: Pacer | None = None,
) -> list[Finding]:
    """Inject CR/LF sequences into params, path, and redirect targets."""
    method_u = (method or "GET").upper()
    if method_u not in {"GET", "POST", "PUT", "PATCH"}:
        return []

    findings: list[Finding] = []
    # Params whose injection was answered by a WAF challenge (never tested):
    # recorded as a coverage gap rather than silently counted clean.
    challenged: dict[str, str] = {}
    normalized = normalize_params(params)
    nonce = secrets.token_hex(4)
    marker = f"shroodler-{nonce}"
    payloads = (
        f"%0d%0aX-Injected: {marker}",
        f"\r\nX-Injected: {marker}",
    )

    for item in normalized:
        name = item["name"]
        for payload in payloads:
            resp = inject(
                url,
                method_u,
                normalized,
                name,
                payload,
                cookie_header=cookie_header,
                client=client,
                pacer=pacer,
            )
            vendor = challenge_vendor(resp)
            if vendor is not None:
                challenged.setdefault(name, vendor)
                continue
            injected = _header_value(resp, _HEADER_NAME)
            blob = _all_header_blob(resp)
            location = _header_value(resp, "location")
            if marker in injected or f"X-Injected: {marker}" in blob:
                findings.append(
                    Finding(
                        id="crlf-header-injection",
                        severity="high",
                        category="payload",
                        url=url,
                        description=(
                            f"{method_u} parameter {name!r} injected a CRLF sequence "
                            "that became a response header."
                        ),
                        evidence=f"param={name} nonce={nonce} header=X-Injected:{marker}",
                        confidence="confirmed",
                    )
                )
            if _looks_redirect(url) and marker in location:
                findings.append(
                    Finding(
                        id="crlf-response-splitting",
                        severity="high",
                        category="payload",
                        url=url,
                        description=(
                            f"{method_u} parameter {name!r} reflected a CRLF payload "
                            "into the Location header."
                        ),
                        evidence=f"param={name} nonce={nonce} location={location[:200]}",
                        confidence="confirmed",
                    )
                )

    cookie_nonce = secrets.token_hex(4)
    cookie_payload = f"%0d%0aSet-Cookie: shroodler={cookie_nonce}"
    path_url = _path_with_crlf(url, cookie_payload)
    resp = request(
        "GET",
        path_url,
        cookie_header=cookie_header,
        client=client,
        pacer=pacer,
    )
    cookie_vendor = challenge_vendor(resp)
    if cookie_vendor is not None:
        challenged.setdefault("path", cookie_vendor)
    else:
        set_cookie = _set_cookie(resp)
        if f"shroodler={cookie_nonce}" in set_cookie:
            findings.append(
                Finding(
                    id="crlf-header-injection",
                    severity="high",
                    category="payload",
                    url=url,
                    description="A CRLF sequence in the URL path became a Set-Cookie header.",
                    evidence=f"nonce={cookie_nonce} set-cookie={set_cookie[:200]}",
                    confidence="confirmed",
                )
            )

    if challenged:
        findings.append(
            probe_challenge_finding(
                url, "crlf", list(challenged), next(iter(challenged.values()))
            )
        )
    return dedupe(findings)
