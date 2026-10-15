"""NoSQL (MongoDB-style) injection probes.

Two detections, both one parameter at a time and both context-aware so a
reflective parameter does not produce a false positive:

* Error-based (confirmed): a driver/ODM parse error (MongoDB, BSON, Mongoose,
  pymongo) that a clean baseline request did not already produce.
* Operator / ``$where`` boolean-differential (heuristic): an always-true value
  behaves like the clean baseline while an always-false value diverges, the
  signature of a value that reaches a MongoDB query or ``$where`` JS context.

Distinct from the SQLi probe: different payloads, different error markers.
"""

from __future__ import annotations

import httpx

from shroodler.models import Finding
from shroodler.pacer import Pacer
from shroodler.probes.common import (
    body_text,
    challenge_vendor,
    dedupe,
    inject,
    normalize_params,
    probe_challenge_finding,
)
from shroodler.waf_detect import expand_if_waf

# Meta-characters and operator fragments that a Mongo/BSON/ODM layer rejects
# when a string value is parsed as a document or coerced to an operator.
_ERROR_PAYLOADS = (
    '"',
    "'",
    "\\",
    "{",
    '{"$gt": ""}',
    "[$ne]",
)

# Always-true / always-false pairs for a value that lands in a ``$where`` JS
# string (``this.x == '<value>'``). The quote break turns the comparison into
# ``... == '' || '1'=='1'`` (true) or ``... == '' || '1'=='2'`` (false).
_WHERE_TRUE = "'||'1'=='1"
_WHERE_FALSE = "'||'1'=='2"

# Markers specific to NoSQL stacks, kept disjoint from the SQLi markers so the
# same endpoint is not reported as both sqli and nosqli.
_ERROR_MARKERS = (
    "MongoError",
    "MongoServerError",
    "MongoParseError",
    "MongooseError",
    "MongoNetworkError",
    "BSONError",
    "BSONTypeError",
    "bson.errors",
    "pymongo",
    "mongoose",  # Mongoose stack frames / "Mongoose" casing handled below
    "CastError",
    "ValidatorError",
    "E11000",
    "unknown operator",
    "unknown top level operator",
    "can't canonicalize query",
    "FailedToParse",
    "$where",
)

_LENGTH_RATIO = 0.20


def _has_nosql_error(body: str) -> bool:
    if not body:
        return False
    lowered = body.lower()
    return any(marker.lower() in lowered for marker in _ERROR_MARKERS)


def _bodies_differ(a: httpx.Response, b: httpx.Response) -> bool:
    a_status = int(getattr(a, "status_code", 0) or 0)
    b_status = int(getattr(b, "status_code", 0) or 0)
    if a_status != b_status:
        return True
    a_len = len(body_text(a))
    b_len = len(body_text(b))
    largest = max(a_len, b_len)
    if largest <= 0:
        return False
    return abs(a_len - b_len) / largest > _LENGTH_RATIO


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


def probe_nosql(
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
) -> list[Finding]:
    """Replay GET/POST/PUT params with NoSQL payloads, one param at a time."""
    method_u = (method or "GET").upper()
    if method_u not in {"GET", "POST", "PUT"}:
        return []
    normalized = normalize_params(params)
    if not normalized:
        return []

    findings: list[Finding] = []
    # Params whose injection was answered by a WAF challenge (never tested):
    # recorded as a coverage gap. Also stops an intermittent challenge on a
    # true/false request from faking an operator-injection diff.
    challenged: dict[str, str] = {}
    error_payloads = expand_if_waf(
        _ERROR_PAYLOADS,
        state=state,
        waf_detected=waf_detected,
        waf_vendor=waf_vendor,
    )

    # Error-based, baseline-differential.
    for item in normalized:
        name = item["name"]
        base_resp = inject(
            url,
            method_u,
            normalized,
            name,
            "shroodler_nosql_baseline",
            cookie_header=cookie_header,
            client=client,
            pacer=pacer,
        )
        baseline_errored = base_resp is not None and _has_nosql_error(
            body_text(base_resp)
        )
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
            vendor = challenge_vendor(resp)
            if vendor is not None:
                challenged.setdefault(name, vendor)
                continue
            if _has_nosql_error(body_text(resp)) and not baseline_errored:
                findings.append(
                    _finding(
                        finding_id="nosqli",
                        url=url,
                        description=(
                            f"{method_u} parameter {name!r} reflected a NoSQL "
                            "driver/ODM error after a NoSQL injection payload "
                            "(absent from a clean baseline request)."
                        ),
                        evidence=f"param={name} payload={payload!r}",
                        confidence="confirmed",
                        severity="critical",
                    )
                )
                return dedupe(findings)

    # Operator / $where boolean-differential, baseline-guarded.
    for item in normalized:
        name = item["name"]
        baseline_value = item.get("value") or "shroodler_nosql_base"
        base_resp = inject(
            url,
            method_u,
            normalized,
            name,
            baseline_value,
            cookie_header=cookie_header,
            client=client,
            pacer=pacer,
        )
        true_resp = inject(
            url,
            method_u,
            normalized,
            name,
            _WHERE_TRUE,
            cookie_header=cookie_header,
            client=client,
            pacer=pacer,
        )
        false_resp = inject(
            url,
            method_u,
            normalized,
            name,
            _WHERE_FALSE,
            cookie_header=cookie_header,
            client=client,
            pacer=pacer,
        )
        if base_resp is None or true_resp is None or false_resp is None:
            continue
        vendor = (
            challenge_vendor(base_resp)
            or challenge_vendor(true_resp)
            or challenge_vendor(false_resp)
        )
        if vendor is not None:
            # A challenge on any of the three skews the comparison: record
            # coverage, do not treat the divergence as operator injection.
            challenged.setdefault(name, vendor)
            continue
        # Injection signature: always-true behaves like the clean baseline
        # (same result set) while always-false diverges. A merely reflective
        # parameter fails the first test because the raw value differs.
        if not _bodies_differ(base_resp, true_resp) and _bodies_differ(
            true_resp, false_resp
        ):
            findings.append(
                _finding(
                    finding_id="nosqli-operator",
                    url=url,
                    description=(
                        f"{method_u} parameter {name!r} matched the clean baseline "
                        "under an always-true NoSQL payload but diverged under an "
                        "always-false one (likely MongoDB operator / $where injection)."
                    ),
                    evidence=(
                        f"param={name} true_status={int(true_resp.status_code)} "
                        f"false_status={int(false_resp.status_code)} "
                        f"true_len={len(body_text(true_resp))} "
                        f"false_len={len(body_text(false_resp))}"
                    ),
                    confidence="heuristic",
                    severity="high",
                )
            )
            break

    if not findings and challenged:
        findings.append(
            probe_challenge_finding(
                url, "nosql", list(challenged), next(iter(challenged.values()))
            )
        )
    return dedupe(findings)
