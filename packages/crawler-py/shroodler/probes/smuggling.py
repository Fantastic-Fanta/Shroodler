"""HTTP request-smuggling probes (CL.TE / TE.CL / TE.TE).

Timing-based. Callers must mock time.monotonic in unit tests so the 5s
desync window is never a real sleep.
"""

from __future__ import annotations

import time
from urllib.parse import urlparse

import httpx

from shroodler.models import Finding
from shroodler.pacer import Pacer
from shroodler.probes.common import body_text, request
from shroodler.urls import is_loopback_or_local

_TIMING_DELTA = 5.0
_TE_TE_VALUES = (
    "xchunked",
    " chunked",
    "chunked, identity",
)


def hostname_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:  # noqa: BLE001
        return ""


def _elapsed(resp: httpx.Response | None, start: float, end: float) -> float:
    if resp is not None:
        elapsed = getattr(resp, "elapsed", None)
        if elapsed is not None:
            try:
                return float(elapsed.total_seconds()) if hasattr(elapsed, "total_seconds") else float(elapsed)
            except (TypeError, ValueError):
                pass
    return max(0.0, end - start)


def _timed(
    method: str,
    url: str,
    *,
    cookie_header: str,
    extra_headers: dict[str, str] | None,
    content: bytes | None,
    client: httpx.Client | None,
    pacer: Pacer | None,
) -> tuple[httpx.Response | None, float]:
    start = time.monotonic()
    kwargs: dict = {}
    if content is not None:
        kwargs["content"] = content
    resp = request(
        method,
        url,
        cookie_header=cookie_header,
        extra_headers=extra_headers,
        client=client,
        pacer=pacer,
        **kwargs,
    )
    end = time.monotonic()
    return resp, _elapsed(resp, start, end)


def _finding(finding_id: str, url: str, evidence: str) -> Finding:
    return Finding(
        id=finding_id,
        severity="critical",
        category="payload",
        url=url,
        description="HTTP request smuggling desynchronization indicated by timing or TE parsing.",
        evidence=evidence,
        confidence="heuristic",
    )


def probe_smuggling(
    url: str,
    cookie_header: str = "",
    *,
    allow_external: bool = False,
    client: httpx.Client | None = None,
    pacer: Pacer | None = None,
) -> list[Finding]:
    """Once-per-host CL.TE / TE.CL timing and TE.TE obfuscation checks."""
    if not allow_external and not is_loopback_or_local(url):
        return []

    findings: list[Finding] = []
    baseline_resp, baseline = _timed(
        "POST",
        url,
        cookie_header=cookie_header,
        extra_headers={"Content-Type": "application/x-www-form-urlencoded"},
        content=b"q=1",
        client=client,
        pacer=pacer,
    )
    baseline_body = body_text(baseline_resp)
    baseline_status = int(getattr(baseline_resp, "status_code", 0) or 0) if baseline_resp else 0

    # CL.TE: Content-Length vs chunked disagree; backend may wait for more data.
    clte_headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": "6",
        "Transfer-Encoding": "chunked",
    }
    clte_body = b"0\r\n\r\nG"
    _clte_resp, clte_elapsed = _timed(
        "POST",
        url,
        cookie_header=cookie_header,
        extra_headers=clte_headers,
        content=clte_body,
        client=client,
        pacer=pacer,
    )
    if clte_elapsed > baseline + _TIMING_DELTA:
        findings.append(
            _finding(
                "http-smuggling-cl-te",
                url,
                f"elapsed={clte_elapsed:.2f}s baseline={baseline:.2f}s",
            )
        )

    # TE.CL: chunked payload with a Content-Length the backend may prefer.
    tecl_headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Transfer-Encoding": "chunked",
        "Content-Length": "4",
    }
    tecl_body = b"5c\r\n" + b"G" * 4 + b"\r\n0\r\n\r\n"
    _tecl_resp, tecl_elapsed = _timed(
        "POST",
        url,
        cookie_header=cookie_header,
        extra_headers=tecl_headers,
        content=tecl_body,
        client=client,
        pacer=pacer,
    )
    if tecl_elapsed > baseline + _TIMING_DELTA:
        findings.append(
            _finding(
                "http-smuggling-te-cl",
                url,
                f"elapsed={tecl_elapsed:.2f}s baseline={baseline:.2f}s",
            )
        )

    for value in _TE_TE_VALUES:
        resp, _elapsed_s = _timed(
            "POST",
            url,
            cookie_header=cookie_header,
            extra_headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Transfer-Encoding": value,
            },
            content=b"0\r\n\r\n",
            client=client,
            pacer=pacer,
        )
        if resp is None:
            continue
        status = int(getattr(resp, "status_code", 0) or 0)
        body = body_text(resp)
        if status != baseline_status or (baseline_body and body != baseline_body):
            findings.append(
                _finding(
                    "http-smuggling-te-te",
                    url,
                    f"te={value!r} status={status} baseline_status={baseline_status}",
                )
            )
            break

    return findings
