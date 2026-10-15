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
            status = int(resp.status_code)
            needle_evil = _EVIL_HOST.lower()
            needle_host = host_value.lower()
            in_location = needle_evil in loc.lower() or needle_host in loc.lower()
            in_body = needle_evil in body.lower() or needle_host in body.lower()
            if not in_location and not in_body:
                continue
            # Severity by reachable impact, not by the mere fact of reflection:
            #  - into a redirect Location, the attacker Host drives where the
            #    victim is sent, so it is directly abusable (open-redirect
            #    phishing, poisoned reset/OAuth-callback links) -> high.
            #  - into the body only (absolute links, og/canonical tags), it is a
            #    Host-trust misconfiguration that reaches a third party ONLY via
            #    an amplifier this single probe cannot confirm (a reset/email
            #    flow that builds links from Host, or a shared cache keyed
            #    without Host) -> medium until such an amplifier is shown.
            redirect = 300 <= status < 400
            high = in_location and redirect
            if high:
                severity = "high"
                where = "the Location header of a redirect"
                impact = (
                    "The injected host controls the redirect target, so it is "
                    "directly usable for open-redirect phishing or to poison "
                    "password-reset / OAuth-callback links."
                )
            else:
                severity = "medium"
                where = "a Location header" if in_location else "the response body"
                impact = (
                    "This reflection alone is a Host-trust misconfiguration, not a "
                    "third-party exploit: it reaches a victim only via an amplifier "
                    "(a password-reset/email flow that builds links from Host, or a "
                    "shared cache keyed without Host). Confirm one before rating it "
                    "high."
                )
            findings.append(
                Finding(
                    id="host-header-injection",
                    severity=severity,
                    category="payload",
                    url=url,
                    description=(
                        f"Response reflected {_EVIL_HOST} in {where} after a "
                        f"{header} header injection. {impact}"
                    ),
                    evidence=(
                        f"header={header}: {host_value} status={status} "
                        f"location={loc!r} "
                        f"where={'location' if in_location else 'body'} "
                        f"redirect={str(redirect).lower()}"
                    ),
                    confidence="confirmed",
                )
            )
            return dedupe(findings)
    return dedupe(findings)
