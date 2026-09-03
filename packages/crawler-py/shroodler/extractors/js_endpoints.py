from __future__ import annotations

import re

from shroodler.models import Finding, JsEndpoint
from shroodler.urls import normalize_url

_FETCH_STR = re.compile(r"""fetch\(\s*['"]([^'"]+)['"]""")
_FETCH_TPL = re.compile(r"fetch\(\s*`([^`$]+)`")
_XHR = re.compile(r"""(?:axios|request)\(\s*['"]([^'"]+)['"]""")


def extract_js_endpoints(source_url: str, js_text: str) -> tuple[list[JsEndpoint], list[Finding]]:
    endpoints: list[JsEndpoint] = []
    findings: list[Finding] = []
    seen: set[str] = set()

    def add(raw: str) -> None:
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

    for m in _FETCH_STR.finditer(js_text):
        add(m.group(1))
    for m in _FETCH_TPL.finditer(js_text):
        add(m.group(1))
    for m in _XHR.finditer(js_text):
        add(m.group(1))
    return endpoints, findings
