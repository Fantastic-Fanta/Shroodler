from __future__ import annotations

import re

from shroodler.models import Finding, JsEndpoint, Page
from shroodler.urls import canonical_key, normalize_url, same_origin

_FETCH_STR = re.compile(r"""fetch\(\s*['"]([^'"]+)['"]""")
_FETCH_TPL = re.compile(r"fetch\(\s*`([^`$]+)`")
_XHR = re.compile(r"""(?:axios|request)\(\s*['"]([^'"]+)['"]""")
_WS_NEW_STR = re.compile(r"""new\s+WebSocket\(\s*['"]([^'"]+)['"]""")
_WS_NEW_TPL = re.compile(r"new\s+WebSocket\(\s*`([^`$]+)`")
_ES_NEW_STR = re.compile(r"""new\s+EventSource\(\s*['"]([^'"]+)['"]""")
_ES_NEW_TPL = re.compile(r"new\s+EventSource\(\s*`([^`$]+)`")
_WS_LIT_STR = re.compile(r"""['"]((?:ws|wss)://[^'"]+)['"]""")
_WS_LIT_TPL = re.compile(r"`((?:ws|wss)://[^`$]+)`")

_PATTERNS = (
    _FETCH_STR,
    _FETCH_TPL,
    _XHR,
    _WS_NEW_STR,
    _WS_NEW_TPL,
    _ES_NEW_STR,
    _ES_NEW_TPL,
    _WS_LIT_STR,
    _WS_LIT_TPL,
)


def extract_js_endpoints(source_url: str, js_text: str) -> tuple[list[JsEndpoint], list[Finding]]:
    endpoints: list[JsEndpoint] = []
    findings: list[Finding] = []
    seen: set[str] = set()

    def add(raw: str) -> None:
        raw = (raw or "").strip()
        if not raw:
            return
        url = normalize_url(source_url, raw) or raw
        if url in seen:
            return
        seen.add(url)
        endpoints.append(JsEndpoint(source=source_url, endpoint=raw))
        findings.append(
            Finding(
                id="js-endpoint",
                severity="info",
                category="js-endpoint",
                url=source_url,
                description=f"JS references endpoint {raw}",
                evidence=raw,
            )
        )

    if not js_text:
        return endpoints, findings
    for pat in _PATTERNS:
        for m in pat.finditer(js_text):
            add(m.group(1))
    return endpoints, findings


def ghost_route_findings(
    origin: str, pages: list[Page], endpoints: list[JsEndpoint]
) -> list[Finding]:
    """Same-origin JS endpoints never recorded in pages[] — do not fetch them."""
    visited = {canonical_key(p.url) for p in pages}
    out: list[Finding] = []
    seen: set[str] = set()
    for ep in endpoints:
        resolved = _resolve_endpoint(origin, ep.source, ep.endpoint)
        if not resolved or not same_origin(resolved, origin):
            continue
        key = canonical_key(resolved)
        if key in visited or key in seen:
            continue
        seen.add(key)
        out.append(
            Finding(
                id="ghost-route",
                severity="info",
                category="js-endpoint",
                url=resolved,
                description="endpoint mentioned in JS but never crawled",
                evidence=ep.source,
            )
        )
    return out


def _resolve_endpoint(origin: str, source: str, endpoint: str) -> str | None:
    base = source if "://" in source else origin
    return normalize_url(base, endpoint) or normalize_url(origin, endpoint)
