"""Missing rate-limit checks on authentication-shaped endpoints.

Distinct from `shroodler.extractors.rate_limit` (login-form hammering during
a crawl). This probe runs from ProbeAction against URL-shaped auth routes.
"""

from __future__ import annotations

import secrets
from urllib.parse import urlparse

import httpx

from shroodler.models import Finding
from shroodler.paced_fetch import pace
from shroodler.pacer import Pacer
from shroodler.probes.common import request

AUTH_HINTS = (
    "login",
    "signin",
    "authenticate",
    "auth",
    "password",
    "reset",
    "forgot",
    "register",
    "signup",
    "verify",
    "otp",
    "2fa",
    "token",
)
_ATTEMPTS = 15
_RATE_HEADERS = ("retry-after", "x-ratelimit-remaining", "x-ratelimit-limit")


def looks_auth_url(url: str) -> bool:
    path = (urlparse(url).path or url or "").lower()
    return any(hint in path for hint in AUTH_HINTS)


def _header(resp: httpx.Response | None, name: str) -> str:
    if resp is None:
        return ""
    headers = getattr(resp, "headers", None) or {}
    try:
        for key, value in headers.items():
            if str(key).lower() == name.lower():
                return str(value)
    except Exception:  # noqa: BLE001
        return ""
    return ""


def _has_rate_signal(resp: httpx.Response | None) -> bool:
    if resp is None:
        return True
    code = int(getattr(resp, "status_code", 0) or 0)
    if code in {429, 503}:
        return True
    for name in _RATE_HEADERS:
        if _header(resp, name):
            return True
    headers = getattr(resp, "headers", None) or {}
    try:
        for key in headers:
            if str(key).lower().startswith("x-ratelimit-"):
                return True
    except Exception:  # noqa: BLE001
        return False
    return False


def probe_rate_limit(
    url: str,
    method: str,
    cookie_header: str,
    *,
    client: httpx.Client | None = None,
    pacer: Pacer | None = None,
    attempts: int = _ATTEMPTS,
) -> list[Finding]:
    """Fire a rapid burst and flag endpoints that never throttle."""
    if not looks_auth_url(url):
        return []
    method_u = (method or "POST").upper()
    if method_u not in {"GET", "POST", "PUT", "PATCH"}:
        return []

    pace(pacer)
    nonce = secrets.token_hex(4)
    extra = {"X-Shroodler-RL-Test": nonce}
    responses: list[httpx.Response] = []
    for _ in range(max(1, int(attempts))):
        # Burst: do not pace between attempts (rapid succession).
        resp = request(
            method_u,
            url,
            cookie_header=cookie_header,
            extra_headers=extra,
            client=client,
            pacer=Pacer(0),
        )
        if resp is None:
            return []
        responses.append(resp)

    if any(_has_rate_signal(resp) for resp in responses):
        return []
    statuses = [int(getattr(r, "status_code", 0) or 0) for r in responses]
    if not statuses or len(set(statuses)) != 1:
        return []
    code = statuses[0]
    if code < 200 or code >= 400:
        return []
    return [
        Finding(
            id="missing-rate-limit",
            severity="medium",
            category="auth",
            url=url,
            description=(
                f"{attempts} rapid {method_u} requests returned {code} with no "
                "429/503, Retry-After, or X-RateLimit-* signal."
            ),
            evidence=f"attempts={attempts} status={code} nonce={nonce}",
            confidence="confirmed",
        )
    ]
