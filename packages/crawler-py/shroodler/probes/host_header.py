"""Host-header injection probes (one URL per hostname)."""

from __future__ import annotations

from urllib.parse import urlparse

import httpx

from shroodler.models import Finding
from shroodler.pacer import Pacer
from shroodler.probes.common import body_text, dedupe, request
from shroodler.waf_detect import expand_if_waf

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
    state=None,
    waf_detected: bool = False,
    waf_vendor: str | None = None,
) -> list[Finding]:
    """Replay the URL with Host / forwarded-host headers pointing at an evil host."""
    if not hostname_of(url):
        return []

    findings: list[Finding] = []
    hosts = expand_if_waf(
        (_EVIL_HOST,),
        state=state,
        waf_detected=waf_detected,
        waf_vendor=waf_vendor,
    )
    for header in _HEADER_NAMES:
        for host_value in hosts:
            resp = request(
                "GET",
                url,
                cookie_header=cookie_header,
                extra_headers={header: host_value},
                client=client,
                pacer=pacer,
            )
            if resp is None:
                continue
            body = body_text(resp)
            loc = _location(resp)
            blob = f"{body}\n{loc}"
            if _EVIL_HOST not in blob.lower() and host_value.lower() not in blob.lower():
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
                        f"header={header}: {host_value} "
                        f"status={int(resp.status_code)} location={loc!r}"
                    ),
                    confidence="confirmed",
                )
            )
            return dedupe(findings)
    return dedupe(findings)
