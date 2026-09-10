"""Open-redirect probes against redirect-like parameters."""

from __future__ import annotations

import secrets

import httpx

from shroodler.models import Finding
from shroodler.pacer import Pacer
from shroodler.probes.common import (
    dedupe,
    inject,
    normalize_params,
)
from shroodler.waf_detect import expand_if_waf

OPEN_REDIRECT_NAME_HINTS = (
    "redirect",
    "return",
    "next",
    "goto",
    "url",
    "target",
    "dest",
    "destination",
    "returnurl",
    "redir",
    "location",
)
_SHORT_NAMES = frozenset({"r", "u"})
_AUTH_URL_HINTS = ("login", "logout", "oauth", "callback", "auth", "sso")
_EVIL_HOST = "evil.example.com"


def param_looks_open_redirect(name: str) -> bool:
    lowered = (name or "").lower()
    if lowered in _SHORT_NAMES:
        return True
    return any(hint in lowered for hint in OPEN_REDIRECT_NAME_HINTS)


def url_looks_auth(url: str) -> bool:
    lowered = (url or "").lower()
    return any(hint in lowered for hint in _AUTH_URL_HINTS)


def _location(resp: httpx.Response | None) -> str:
    if resp is None:
        return ""
    headers = getattr(resp, "headers", None) or {}
    try:
        value = headers.get("location") or headers.get("Location") or ""
    except Exception:  # noqa: BLE001
        return ""
    return str(value)


def _is_redirect(resp: httpx.Response | None) -> bool:
    if resp is None:
        return False
    status = int(getattr(resp, "status_code", 0) or 0)
    return 300 <= status < 400


def _payloads(nonce: str) -> tuple[str, ...]:
    return (
        f"https://{_EVIL_HOST}/shroodler-redirect-{nonce}",
        f"//{_EVIL_HOST}/shroodler-redirect-{nonce}",
        f"/\\{_EVIL_HOST}",
    )


def probe_open_redirect(
    url: str,
    method: str,
    params: list[dict],
    cookie_header: str,
    *,
    client: httpx.Client | None = None,
    pacer: Pacer | None = None,
    state=None,
    waf_detected: bool = False,
    waf_vendor: str | None = None,
) -> list[Finding]:
    """Replay redirect-like params (or all params on login-like URLs)."""
    method_u = (method or "GET").upper()
    if method_u not in {"GET", "POST"}:
        return []
    normalized = normalize_params(params)
    if not normalized:
        return []
    probe_all = url_looks_auth(url)
    candidates = [
        item
        for item in normalized
        if probe_all or param_looks_open_redirect(item["name"])
    ]
    if not candidates:
        return []

    findings: list[Finding] = []
    for item in candidates:
        name = item["name"]
        nonce = secrets.token_hex(6)
        for payload in expand_if_waf(
            _payloads(nonce),
            state=state,
            waf_detected=waf_detected,
            waf_vendor=waf_vendor,
        ):
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
            if not _is_redirect(resp):
                continue
            loc = _location(resp)
            if _EVIL_HOST not in loc.lower():
                continue
            findings.append(
                Finding(
                    id="open-redirect",
                    severity="medium",
                    category="payload",
                    url=url,
                    description=(
                        f"{method_u} parameter {name!r} issued a 3xx Location "
                        f"pointing at {_EVIL_HOST}."
                    ),
                    evidence=(
                        f"param={name} payload={payload!r} "
                        f"status={int(resp.status_code)} location={loc!r}"
                    ),
                    confidence="confirmed",
                )
            )
            return dedupe(findings)
    return dedupe(findings)
