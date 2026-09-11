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


_BYPASS_ATTEMPTS = 20
# Fixed, documentation-range source used for the control burst (RFC 5737).
_FIXED_XFF = "203.0.113.7"


def _rotating_xff() -> dict[str, str]:
    """A unique, public-looking X-Forwarded-For per call."""
    a = 1 + secrets.randbelow(223)
    b, c = secrets.randbelow(256), secrets.randbelow(256)
    d = 1 + secrets.randbelow(254)
    return {"X-Forwarded-For": f"{a}.{b}.{c}.{d}"}


def probe_rate_limit_bypass(
    url: str,
    method: str,
    cookie_header: str,
    *,
    client: httpx.Client | None = None,
    pacer: Pacer | None = None,
    attempts: int = _BYPASS_ATTEMPTS,
) -> list[Finding]:
    """Flag rate limiters that key on the spoofable X-Forwarded-For header.

    Two bursts: one with a fixed X-Forwarded-For (must throttle, proving a
    limiter exists), then one rotating X-Forwarded-For per request. If the
    second burst never throttles, the limiter is keyed on the client-supplied
    header and an attacker defeats it by rotating that header — e.g. to brute
    force an auth endpoint. Bounded, so it only catches low-threshold limits
    (which is where bypass matters most); high-ceiling limits are left alone.
    """
    if not looks_auth_url(url):
        return []
    method_u = (method or "POST").upper()
    if method_u not in {"GET", "POST", "PUT", "PATCH"}:
        return []
    pace(pacer)
    nonce = secrets.token_hex(4)
    n = max(1, int(attempts))

    tripped = False
    fixed = {"X-Shroodler-RLB": nonce, "X-Forwarded-For": _FIXED_XFF}
    for _ in range(n):
        resp = request(
            method_u, url, cookie_header=cookie_header,
            extra_headers=fixed, client=client, pacer=Pacer(0),
        )
        if resp is None:
            return []
        if _has_rate_signal(resp):
            tripped = True
            break
    if not tripped:
        # No limiter tripped within the budget — nothing to bypass here
        # (missing-rate-limit is a separate probe's job).
        return []

    for _ in range(n):
        headers = {"X-Shroodler-RLB": nonce, **_rotating_xff()}
        resp = request(
            method_u, url, cookie_header=cookie_header,
            extra_headers=headers, client=client, pacer=Pacer(0),
        )
        if resp is None:
            return []
        if _has_rate_signal(resp):
            return []  # rotating XFF still throttled — limiter keys on real IP

    return [
        Finding(
            id="rate-limit-bypass-forwarded-for",
            severity="high",
            category="auth",
            url=url,
            description=(
                "Endpoint throttles a fixed client but not when X-Forwarded-For "
                "is rotated per request: the rate limiter trusts the "
                "client-supplied header, so an attacker bypasses it (e.g. to "
                "brute force credentials)."
            ),
            evidence=f"fixed_burst_tripped rotating_xff_bypassed attempts={n} nonce={nonce}",
            confidence="confirmed",
        )
    ]
