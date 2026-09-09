"""Error-based and time-based SQL injection probes."""

from __future__ import annotations

import json

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

_ERROR_PAYLOADS = (
    "'",
    "' OR '1'='1",
    "'; --",
    "1 AND 1=2",
)
_TIME_PAYLOAD = "'; WAITFOR DELAY '0:0:2'--"
_ERROR_MARKERS = (
    "SQL syntax",
    "ORA-",
    "MySQL",
    "sqlite",
    "SQLSTATE",
    "Unclosed quotation",
    "syntax error",
    "pg_query",
    "Warning: mysql",
    "You have an error in your SQL syntax",
    "SqlException",
    "HsqlException",
    "JdbcSQLSyntaxErrorException",
    "unexpected token",
    "org.h2.jdbc",
)
_TIME_THRESHOLD = 2.0


def _has_sql_error(body: str) -> bool:
    if not body:
        return False
    lowered = body.lower()
    return any(marker.lower() in lowered for marker in _ERROR_MARKERS)


def _webgoat_lesson_output(resp: httpx.Response | None, body: str) -> bool:
    """WebGoat confirms injection by returning lesson JSON with a non-empty output."""
    if resp is None or int(getattr(resp, "status_code", 0) or 0) != 200:
        return False
    if "lessoncompleted" not in (body or "").lower():
        return False
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    output = data.get("output")
    if output is None:
        return False
    if isinstance(output, str):
        return bool(output.strip())
    return bool(output)


def _finding(
    *,
    finding_id: str,
    url: str,
    description: str,
    evidence: str,
    confidence: str,
) -> Finding:
    return Finding(
        id=finding_id,
        severity="critical",
        category="payload",
        url=url,
        description=description,
        evidence=evidence,
        confidence=confidence,  # type: ignore[arg-type]
    )


def probe_sqli(
    url: str,
    method: str,
    params: list[dict],
    cookie_header: str,
    *,
    client: httpx.Client | None = None,
    pacer: Pacer | None = None,
) -> list[Finding]:
    """Replay GET/POST params with classic SQLi payloads, one param at a time."""
    method_u = (method or "GET").upper()
    if method_u not in {"GET", "POST"}:
        return []
    normalized = normalize_params(params)
    if not normalized:
        return []

    findings: list[Finding] = []
    baseline = request(
        method_u,
        url,
        cookie_header=cookie_header,
        client=client,
        pacer=pacer,
    )
    baseline_elapsed = response_elapsed(baseline, 0.0) if baseline is not None else 0.0
    saw_error = False
    saw_time = False

    for item in normalized:
        name = item["name"]
        if not saw_error:
            for payload in _ERROR_PAYLOADS:
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
                if _has_sql_error(body) or _webgoat_lesson_output(resp, body):
                    findings.append(
                        _finding(
                            finding_id="sqli",
                            url=url,
                            description=(
                                f"{method_u} parameter {name!r} reflected a database "
                                "error after a SQL injection payload."
                            ),
                            evidence=f"param={name} payload={payload!r}",
                            confidence="confirmed",
                        )
                    )
                    saw_error = True
                    break
        if saw_time:
            continue
        resp = inject(
            url,
            method_u,
            normalized,
            name,
            _TIME_PAYLOAD,
            cookie_header=cookie_header,
            client=client,
            pacer=pacer,
        )
        if resp is None:
            continue
        elapsed = response_elapsed(resp, 0.0)
        if elapsed > baseline_elapsed + _TIME_THRESHOLD:
            findings.append(
                _finding(
                    finding_id="sqli-blind",
                    url=url,
                    description=(
                        f"{method_u} parameter {name!r} delayed the response by more "
                        "than 2s after a WAITFOR DELAY payload (blind SQLi)."
                    ),
                    evidence=(
                        f"param={name} elapsed={elapsed:.2f}s "
                        f"baseline={baseline_elapsed:.2f}s"
                    ),
                    confidence="heuristic",
                )
            )
            saw_time = True
        if saw_error and saw_time:
            break

    return dedupe(findings)
