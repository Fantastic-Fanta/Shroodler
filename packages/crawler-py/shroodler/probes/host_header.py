"""Host-header injection probes (one URL per hostname)."""

from __future__ import annotations

from urllib.parse import urlparse

import httpx

from shroodler.models import Finding
from shroodler.pacer import Pacer
from shroodler.probes.common import body_text, dedupe, request

_EVIL_HOST = "evil.example.com"
_HEADER_NAMES = ("Host", "X-Forwarded-Host", "X-Host")


def hostname_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:  # noqa: BLE001
        return ""


def _location(resp: httpx.Response | None) -> str:
    if resp is None:
        return ""
    headers = getattr(resp, "headers", None) or {}
    try:
        return str(headers.get("location") or headers.get("Location") or "")
    except Exception:  # noqa: BLE001
        return ""


def probe_host_header(
    url: str,
    cookie_header: str,
    *,
    client: httpx.Client | None = None,
    pacer: Pacer | None = None,
) -> list[Finding]:
    """Replay the URL with Host / forwarded-host headers pointing at an evil host."""
    if not hostname_of(url):
        return []

    findings: list[Finding] = []
    for header in _HEADER_NAMES:
        resp = request(
            "GET",
            url,
            cookie_header=cookie_header,
            extra_headers={header: _EVIL_HOST},
            client=client,
            pacer=pacer,
        )
        if resp is None:
            continue
        body = body_text(resp)
        loc = _location(resp)
        blob = f"{body}\n{loc}"
        if _EVIL_HOST not in blob.lower():
            continue
        findings.append(
            Finding(
                id="host-header-injection",
                severity="high",
                category="payload",
                url=url,
                description=(
                    f"Response body or Location reflected {_EVIL_HOST} after a "
                    f"{header} header injection."
                ),
                evidence=(
                    f"header={header}: {_EVIL_HOST} "
                    f"status={int(resp.status_code)} location={loc!r}"
                ),
                confidence="confirmed",
            )
        )
        return dedupe(findings)
    return dedupe(findings)
