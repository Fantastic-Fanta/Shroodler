"""Web cache poisoning probe (unkeyed-header reflection into a cacheable response).

Poisoning requires two things together: a header the cache does *not* key on,
and a response the cache *will* store and serve to other users. Either alone is
not poisoning, so this probe confirms both:

* an unkeyed request header (X-Forwarded-Host/-Scheme/-Proto, X-Host, ...) whose
  random marker value comes back in the response body or headers, and
* cache headers (Age, X-Cache, CF-Cache-Status, Cache-Control: public/max-age)
  showing the response is cacheable.

Non-destructive: every request carries a unique cache-buster query parameter, so
the test exercises a throwaway cache key and never poisons the canonical one.
Reported heuristic -- safely confirming cross-user poisoning would mean writing
to the shared cache, which the probe deliberately does not do.
"""

from __future__ import annotations

import uuid
from urllib.parse import urlencode, urlparse, urlunparse

import httpx

from shroodler.models import Finding
from shroodler.pacer import Pacer
from shroodler.probes.common import body_text, dedupe, request

# Headers an origin often trusts but a CDN/cache usually does not key on.
_UNKEYED_HEADERS = (
    "X-Forwarded-Host",
    "X-Forwarded-Scheme",
    "X-Forwarded-Proto",
    "X-Forwarded-Port",
    "X-Host",
    "X-Original-URL",
    "X-Rewrite-URL",
)

# Any of these on the response means a cache layer may store it.
_CACHE_HEADER_NAMES = (
    "age",
    "x-cache",
    "x-cache-hits",
    "cf-cache-status",
    "x-served-by",
    "x-varnish",
    "x-drupal-cache",
    "x-proxy-cache",
)


def _cache_buster(url: str, token: str) -> str:
    parsed = urlparse(url)
    query = parsed.query
    buster = urlencode({"shroodler_cb": token})
    new_query = f"{query}&{buster}" if query else buster
    return urlunparse(parsed._replace(query=new_query))


def _is_cacheable(resp: httpx.Response) -> bool:
    headers = getattr(resp, "headers", None) or {}
    try:
        items = {str(k).lower(): str(v).lower() for k, v in headers.items()}
    except Exception:  # noqa: BLE001
        return False
    cache_control = items.get("cache-control", "")
    if any(tok in cache_control for tok in ("no-store", "private", "no-cache")):
        return False
    if any(name in items for name in _CACHE_HEADER_NAMES):
        return True
    if "public" in cache_control:
        return True
    if "max-age=" in cache_control:
        # max-age=0 is not cacheable in a useful way.
        return "max-age=0" not in cache_control
    return False


def _reflects(resp: httpx.Response, marker: str) -> str | None:
    """Return where the marker was reflected (body/header), or None."""
    marker_l = marker.lower()
    if marker_l in body_text(resp).lower():
        return "body"
    headers = getattr(resp, "headers", None) or {}
    try:
        for key, value in headers.items():
            if marker_l in str(value).lower():
                return f"header:{key}"
    except Exception:  # noqa: BLE001
        return None
    return None


def probe_cache_poisoning(
    url: str,
    cookie_header: str,
    *,
    client: httpx.Client | None = None,
    pacer: Pacer | None = None,
    state=None,
    waf_detected: bool = False,
    waf_vendor: str | None = None,
) -> list[Finding]:
    """Look for an unkeyed header reflected into a cacheable response."""
    if not urlparse(url).hostname:
        return []

    findings: list[Finding] = []
    for header in _UNKEYED_HEADERS:
        token = uuid.uuid4().hex[:16]
        marker = f"shroodler{token}.example"
        busted = _cache_buster(url, token)
        resp = request(
            "GET",
            busted,
            cookie_header=cookie_header,
            extra_headers={header: marker},
            client=client,
            pacer=pacer,
        )
        if resp is None:
            continue
        where = _reflects(resp, marker)
        if where is None:
            continue
        if not _is_cacheable(resp):
            continue
        findings.append(
            Finding(
                id="cache-poisoning-unkeyed-header",
                severity="high",
                category="payload",
                url=url,
                description=(
                    f"The {header} request header was reflected into a cacheable "
                    f"response ({where}); a cache that does not key on {header} "
                    "could serve the attacker-controlled value to other users."
                ),
                evidence=(
                    f"header={header} reflected_in={where} "
                    f"status={int(resp.status_code)} marker={marker}"
                ),
                confidence="heuristic",
            )
        )
        return dedupe(findings)
    return dedupe(findings)
