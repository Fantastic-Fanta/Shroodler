"""Unauthenticated access to sensitive, user-scoped API endpoints.

Catches broken access control of the confused-deputy / missing-auth kind: an
endpoint whose path clearly serves user-scoped or privileged data returns 200
with real structured data when called with NO credentials. This is the class
behind e.g. an unauthenticated `GET /api/channels/{id}/messages`.

Read-only (GET). Precision comes from two gates: the path must look
user-scoped/sensitive, and the anonymous response must be structured data that
is not an auth-error body. Confidence is `probable`, not `confirmed`, because a
few such paths are legitimately public.
"""

from __future__ import annotations

from urllib.parse import urlparse

import httpx

from shroodler.models import Finding
from shroodler.pacer import Pacer
from shroodler.probes.common import body_text, request

# Path fragments that imply per-user, private, or privileged data.
SENSITIVE_HINTS = (
    "/me",
    "/admin",
    "/account",
    "/user",
    "/users",
    "/message",
    "/channel",
    "/dm/",
    "/private",
    "/internal",
    "/save",
    "/order",
    "/profile",
    "/settings",
    "/billing",
    "/note",
    "/drive",
    "/relationship",
    "/guild",
    "/session",
    "/inbox",
    "/wallet",
    "/payment",
)

# Bodies that mean "auth is enforced" — not an exposure.
_AUTH_ERROR_MARKERS = (
    "not authenticated",
    "unauthorized",
    "not logged in",
    "login required",
    "authentication required",
    "forbidden",
    "permission denied",
    "access denied",
    "invalid token",
    "missing token",
)


def _path_is_sensitive(url: str) -> bool:
    path = (urlparse(url).path or "").lower()
    return any(hint in path for hint in SENSITIVE_HINTS)


def _content_type(resp: httpx.Response) -> str:
    try:
        return str((resp.headers or {}).get("content-type") or "").lower()
    except Exception:  # noqa: BLE001
        return ""


def _looks_structured(body: str, ctype: str) -> bool:
    if "json" in ctype:
        return True
    stripped = (body or "").lstrip()
    return stripped[:1] in {"{", "["}


def probe_unauth_exposure(
    url: str,
    method: str,
    *,
    client: httpx.Client | None = None,
    pacer: Pacer | None = None,
) -> list[Finding]:
    """Request a sensitive-looking endpoint with no credentials; flag a 200
    that returns structured data instead of an auth error."""
    method_u = (method or "GET").upper()
    if method_u != "GET":  # read-only; never probe writes anonymously
        return []
    if not _path_is_sensitive(url):
        return []
    resp = request("GET", url, cookie_header="", client=client, pacer=pacer)
    if resp is None:
        return []
    if int(getattr(resp, "status_code", 0) or 0) != 200:
        return []
    ctype = _content_type(resp)
    if "text/html" in ctype:  # SPA shell / catch-all, not an API payload
        return []
    body = body_text(resp) or ""
    if not _looks_structured(body, ctype):
        return []
    if len(body.strip()) < 2:
        return []
    low = body.lower()
    if any(marker in low for marker in _AUTH_ERROR_MARKERS):
        return []
    path = urlparse(url).path or url
    return [
        Finding(
            id="unauthenticated-data-exposure",
            severity="high",
            category="auth",
            url=url,
            description=(
                "A user-scoped or privileged API endpoint returned 200 with "
                "structured data when requested with no authentication — broken "
                "access control (missing auth / confused deputy)."
            ),
            evidence=f"path={path} anon_status=200 bytes={len(body)} content_type={ctype}",
            confidence="probable",
        )
    ]
