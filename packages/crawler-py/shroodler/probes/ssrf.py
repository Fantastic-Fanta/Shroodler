"""SSRF probes against URL-like parameters."""

from __future__ import annotations

import secrets
import socket
import threading
from collections.abc import Callable

import httpx

from shroodler.models import Finding
from shroodler.pacer import Pacer
from shroodler.probes.common import (
    body_text,
    dedupe,
    inject,
    normalize_params,
    request,
    response_elapsed,
)

SSRF_NAME_HINTS = (
    "url",
    "uri",
    "path",
    "redirect",
    "link",
    "src",
    "source",
    "host",
    "endpoint",
    "callback",
    "webhook",
    "fetch",
    "load",
    "import",
    "proxy",
    "target",
    "dest",
    "destination",
    "next",
    "return",
    "returnurl",
    "goto",
)
_METADATA_PAYLOAD = "http://169.254.169.254/latest/meta-data/"
_LOCALHOST_PAYLOAD = "http://localhost/"
_METADATA_MARKERS = ("instance-id", "ami-id", "root:")
_TIMING_THRESHOLD = 2.0
ListenFn = Callable[[float], tuple[int, Callable[[], bool]]]


def param_looks_ssrf(name: str) -> bool:
    lowered = (name or "").lower()
    return any(hint in lowered for hint in SSRF_NAME_HINTS)


def _default_listen(timeout: float) -> tuple[int, Callable[[], bool]]:
    """One-shot TCP listener on 127.0.0.1; returns (port, wait_for_hit)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    port = int(sock.getsockname()[1])
    sock.listen(1)
    sock.settimeout(max(0.0, float(timeout)))
    hit = {"ok": False}

    def _accept() -> None:
        try:
            conn, _addr = sock.accept()
            hit["ok"] = True
            try:
                conn.close()
            except OSError:
                pass
        except OSError:
            pass
        finally:
            try:
                sock.close()
            except OSError:
                pass

    thread = threading.Thread(target=_accept, daemon=True)
    thread.start()

    def wait_for_hit() -> bool:
        thread.join(timeout=max(0.0, float(timeout)) + 0.5)
        return bool(hit["ok"])

    return port, wait_for_hit


def _finding(
    *,
    finding_id: str,
    url: str,
    description: str,
    evidence: str,
    confidence: str,
    severity: str,
) -> Finding:
    return Finding(
        id=finding_id,
        severity=severity,  # type: ignore[arg-type]
        category="payload",
        url=url,
        description=description,
        evidence=evidence,
        confidence=confidence,  # type: ignore[arg-type]
    )


def _oob_payload(port: int, nonce: str) -> str:
    return f"http://127.0.0.1:{port}/ssrf-{nonce}"


def _body_has_metadata(body: str) -> bool:
    text = body or ""
    lowered = text.lower()
    return any(marker.lower() in lowered for marker in _METADATA_MARKERS)


def probe_ssrf(
    url: str,
    method: str,
    params: list[dict],
    cookie_header: str,
    *,
    client: httpx.Client | None = None,
    pacer: Pacer | None = None,
    listen_fn: ListenFn | None = None,
    oob_timeout: float = 5.0,
) -> list[Finding]:
    """Inject loopback/metadata URLs into URL-like params and watch for SSRF."""
    method_u = (method or "GET").upper()
    if method_u not in {"GET", "POST"}:
        return []
    candidates = [item for item in normalize_params(params) if param_looks_ssrf(item["name"])]
    if not candidates:
        return []

    findings: list[Finding] = []
    listen = listen_fn or _default_listen
    normalized = normalize_params(params)

    baseline_resp = request(
        method_u,
        url,
        cookie_header=cookie_header,
        client=client,
        pacer=pacer,
    )
    baseline = response_elapsed(baseline_resp, 0.0) if baseline_resp is not None else 0.0

    for item in candidates:
        name = item["name"]
        nonce = secrets.token_hex(8)
        oob_hit = False
        oob_resp: httpx.Response | None = None
        oob_url = ""
        try:
            port, wait_for_hit = listen(oob_timeout)
            oob_url = _oob_payload(port, nonce)
            oob_resp = inject(
                url,
                method_u,
                normalized,
                name,
                oob_url,
                cookie_header=cookie_header,
                client=client,
                pacer=pacer,
            )
            oob_hit = bool(wait_for_hit())
        except Exception:  # noqa: BLE001 - fail closed
            oob_hit = False
        if oob_hit:
            findings.append(
                _finding(
                    finding_id="ssrf-oob",
                    url=url,
                    description=(
                        f"{method_u} parameter {name!r} triggered an outbound "
                        "connection to a loopback listener (SSRF)."
                    ),
                    evidence=f"param={name} payload={oob_url!r} nonce={nonce}",
                    confidence="confirmed",
                    severity="critical",
                )
            )
            continue

        metadata_hit = False
        for payload in (_METADATA_PAYLOAD, _LOCALHOST_PAYLOAD):
            resp = inject(
                url,
                method_u,
                normalized,
                name,
                payload,
                cookie_header=cookie_header,
                client=client,
                pacer=pacer,
            )
            if resp is None:
                continue
            body = body_text(resp)
            if _body_has_metadata(body):
                findings.append(
                    _finding(
                        finding_id="ssrf-oob",
                        url=url,
                        description=(
                            f"{method_u} parameter {name!r} returned an internal "
                            "metadata or localhost body after an SSRF payload."
                        ),
                        evidence=f"param={name} payload={payload!r}",
                        confidence="confirmed",
                        severity="critical",
                    )
                )
                metadata_hit = True
                break
        if metadata_hit:
            continue

        body = body_text(oob_resp)
        elapsed = response_elapsed(oob_resp, 0.0) if oob_resp is not None else 0.0
        reflected = bool(oob_url) and (oob_url in body or nonce in body)
        unusual_timing = (
            oob_resp is not None
            and baseline <= _TIMING_THRESHOLD
            and elapsed > baseline + _TIMING_THRESHOLD
        )
        if reflected or unusual_timing:
            findings.append(
                _finding(
                    finding_id="ssrf-reflected",
                    url=url,
                    description=(
                        f"{method_u} parameter {name!r} reflected an SSRF URL "
                        "or delayed while fetching it."
                    ),
                    evidence=(
                        f"param={name} payload={oob_url!r} elapsed={elapsed:.2f}s "
                        f"baseline={baseline:.2f}s reflected={str(reflected).lower()}"
                    ),
                    confidence="heuristic",
                    severity="high",
                )
            )

    return dedupe(findings)
