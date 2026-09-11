"""LLM-driven tools that read results and reason further.

- ``craft_payloads``  — the model writes payloads tailored to what it has
                        already observed (stack, error strings, reflection
                        context); this layer fires them and reports back
                        exactly what happened, so the model reasons on
                        real evidence instead of a fixed list.
- ``verify_finding``  — re-fetch a finding's URL and have the model judge,
                        from fresh evidence, whether it is real. Confirms,
                        downgrades, or drops false positives. Directly cuts
                        the false-positive rate.
- ``analyze_logic``   — reason about business-logic abuse (price tampering,
                        coupon reuse, step-skipping, negative quantities)
                        from the crawled workflow, and queue hypotheses.

All fail closed: no key / bad JSON / transport error yields a ToolResult
whose summary says why, and no state is corrupted.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from shroodler.llm_agent.executor import ToolResult, _auth, _params_of
from shroodler.llm_agent.http_tools import _observe, _send, reflection_context
from shroodler.llm_agent.llm_call import complete_json, wrap_untrusted
from shroodler.llm_agent.planner import PlannerDecision
from shroodler.pacer import Pacer
from shroodler.probes.common import request

# Substrings that strongly suggest a database error surfaced to the client.
_SQL_ERROR_SIGNALS = (
    "sql syntax",
    "mysql_fetch",
    "you have an error in your sql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg_query",
    "psql:",
    "sqlite3.operationalerror",
    "ora-01756",
    "odbc sql server driver",
    "syntax error at or near",
)

_MAX_PAYLOADS = 12
_CRAFT_SYSTEM = (
    "You are an expert penetration tester crafting payloads for an authorized "
    "test. Given a vulnerability class, a target parameter, and evidence "
    "already observed, produce payloads specifically tailored to that evidence "
    "(the detected database, template engine, framework, WAF, or reflection "
    "context). Prefer a few high-signal payloads over many generic ones. "
    'Respond with JSON only: {"payloads": ["..."], "rationale": "one sentence"}.'
)
_VERIFY_SYSTEM = (
    "You are a senior bug-bounty triage analyst. Given a reported finding and "
    "a fresh response captured from its URL, decide whether the finding is a "
    "real, exploitable issue or a false positive. Be strict: benign reflection, "
    "a generic error page, or a 403/redirect is not a vulnerability. "
    'Respond with JSON only: {"verdict": "confirmed|likely|false_positive", '
    '"confidence": "confirmed|probable|heuristic", "reasoning": "one sentence"}.'
)
_LOGIC_SYSTEM = (
    "You are an expert at finding business-logic and authorization flaws that "
    "signature scanners miss. Given a crawled web app's endpoints and any "
    "confirmed findings, infer the intended workflow and propose concrete abuse "
    "cases: price/parameter tampering, coupon or token reuse, step-skipping, "
    "negative or overflow quantities, IDOR across related endpoints, race "
    "conditions, and privilege boundaries. "
    'Respond with JSON only: {"hypotheses": [{"hypothesis": "...", '
    '"target_url": "...", "reasoning": "...", "severity": "low|medium|high|critical"}]}.'
)
_VALID_CONFIDENCE = {"confirmed", "probable", "heuristic"}


def _classify_payload_result(vuln_class: str, payload: str, obs: dict[str, Any]) -> str:
    body = str(obs.get("body") or "")
    low = body.lower()
    vc = str(vuln_class or "").lower()
    if "sql" in vc and any(sig in low for sig in _SQL_ERROR_SIGNALS):
        return "sql-error-reflected"
    if "ssti" in vc or "template" in vc:
        # Common arithmetic markers evaluated server-side.
        for probe, expect in (("7*7", "49"), ("7*'7'", "7777777")):
            if probe in payload and expect in body:
                return "template-evaluated"
    if "xss" in vc:
        ctx = reflection_context(body, payload)
        if ctx in {"script", "attribute", "tag"}:
            return f"reflected-in-{ctx}"
    if payload and payload in body:
        return "reflected"
    return "no-signal"


def craft_payloads(
    decision: PlannerDecision,
    state: Any,
    config: Any,
    pacer: Pacer,
    client: Any | None,
) -> ToolResult:
    params = _params_of(decision)
    url = str(params.get("url") or "").strip()
    param = str(params.get("param") or "").strip()
    vuln_class = str(params.get("vuln_class") or params.get("class") or "").strip()
    method = str(params.get("method") or "GET").upper()
    evidence = str(params.get("evidence") or "")
    if not url or not vuln_class:
        return ToolResult(
            summary="craft_payloads needs url and vuln_class",
            raw_output={"error": "missing url/vuln_class"},
        )
    user = (
        f"VULN CLASS: {vuln_class}\nURL: {url}\nPARAM: {param or '(none — target the URL)'}\n"
        f"METHOD: {method}\nOBSERVED EVIDENCE:\n{wrap_untrusted(evidence)}\n\n"
        "Return tailored payloads as JSON."
    )
    call = complete_json(_CRAFT_SYSTEM, user, config, max_tokens=600)
    if call.data is None:
        return ToolResult(
            summary=f"craft_payloads llm unavailable: {call.error}",
            raw_output={"error": call.error},
        )
    raw_payloads = call.data.get("payloads")
    if isinstance(raw_payloads, list):
        payloads = [str(p) for p in raw_payloads if str(p).strip()][:_MAX_PAYLOADS]
    else:
        payloads = []
    if not payloads:
        return ToolResult(
            summary="craft_payloads produced no payloads",
            raw_output={"error": "empty", "rationale": call.data.get("rationale")},
        )
    cookie_header, _peer = _auth(config)
    results: list[dict[str, Any]] = []
    interesting = 0
    for payload in payloads:
        send_params = {param: payload} if param else None
        body = None
        if not param and method != "GET":
            body = payload
        resp, target, needles = _send(
            method,
            url,
            headers=None,
            body=body,
            params=send_params,
            cookie_header=cookie_header,
            client=client,
            pacer=pacer,
        )
        obs = _observe(resp, needles or [payload])
        signal = _classify_payload_result(vuln_class, payload, obs)
        if signal != "no-signal":
            interesting += 1
        results.append(
            {
                "payload": payload,
                "status_code": obs.get("status_code"),
                "elapsed_s": obs.get("elapsed_s"),
                "bytes": obs.get("bytes"),
                "signal": signal,
            }
        )
    summary = (
        f"craft_payloads {vuln_class} on {param or url}: tried {len(results)}, "
        f"{interesting} with a signal"
    )
    return ToolResult(
        findings_added=0,
        summary=summary,
        raw_output={
            "vuln_class": vuln_class,
            "url": url,
            "param": param,
            "rationale": call.data.get("rationale"),
            "results": results,
        },
    )


def _find_finding(state: Any, finding_id: str, url: str = "") -> Any:
    for f in getattr(state, "findings", None) or []:
        if str(getattr(f, "id", "")) == finding_id:
            if not url or str(getattr(f, "url", "")) == url:
                return f
    return None


def _verify_one(
    finding: Any,
    state: Any,
    config: Any,
    pacer: Pacer,
    client: Any | None,
) -> dict[str, Any]:
    """Judge one finding against fresh evidence and apply the verdict.

    Returns {verdict, confidence, reasoning, removed} or {error}. Mutates
    the finding's confidence, or drops it from state on false_positive.
    """
    finding_id = str(getattr(finding, "id", "") or "")
    url = str(getattr(finding, "url", "") or "")
    cookie_header, _peer = _auth(config)
    resp = (
        request("GET", url, cookie_header=cookie_header, client=client, pacer=pacer)
        if url
        else None
    )
    fresh = _observe(resp, []) if resp is not None else {"status_code": 0, "body": ""}
    user = (
        f"FINDING id={finding_id} severity={getattr(finding, 'severity', '')} "
        f"category={getattr(finding, 'category', '')}\n"
        f"URL: {url}\n"
        f"DESCRIPTION: {getattr(finding, 'description', '')}\n"
        f"ORIGINAL EVIDENCE: {getattr(finding, 'evidence', '') or '(none)'}\n\n"
        f"FRESH RESPONSE status={fresh.get('status_code')} "
        f"bytes={fresh.get('bytes')} content_type={fresh.get('content_type', '')}\n"
        f"{wrap_untrusted(str(fresh.get('body') or ''))}\n\n"
        "Judge whether this finding is real. Return JSON only."
    )
    call = complete_json(_VERIFY_SYSTEM, user, config, use_reasoning=True, max_tokens=400)
    if call.data is None:
        return {"error": call.error, "finding_id": finding_id}
    verdict = str(call.data.get("verdict") or "").lower().strip()
    reasoning = " ".join(str(call.data.get("reasoning") or "").split())[:200]
    if verdict == "false_positive":
        try:
            state.findings = [
                f for f in state.findings if str(getattr(f, "id", "")) != finding_id
            ]
        except Exception:  # noqa: BLE001
            pass
        return {
            "finding_id": finding_id,
            "verdict": "false_positive",
            "removed": True,
            "reasoning": reasoning,
        }
    new_conf = str(call.data.get("confidence") or "").lower().strip()
    if new_conf not in _VALID_CONFIDENCE:
        new_conf = "confirmed" if verdict == "confirmed" else "probable"
    try:
        finding.confidence = new_conf
    except Exception:  # noqa: BLE001
        pass
    return {
        "finding_id": finding_id,
        "verdict": verdict or "kept",
        "confidence": new_conf,
        "removed": False,
        "reasoning": reasoning,
    }


def verify_finding(
    decision: PlannerDecision,
    state: Any,
    config: Any,
    pacer: Pacer,
    client: Any | None,
) -> ToolResult:
    params = _params_of(decision)
    finding_id = str(params.get("finding_id") or params.get("id") or "").strip()
    if not finding_id:
        return ToolResult(
            summary="verify_finding missing finding_id",
            raw_output={"error": "missing id"},
        )
    finding = _find_finding(state, finding_id, str(params.get("url") or ""))
    if finding is None:
        return ToolResult(
            summary=f"verify_finding: no finding {finding_id} in state",
            raw_output={"error": "not found", "finding_id": finding_id},
        )
    out = _verify_one(finding, state, config, pacer, client)
    if out.get("error"):
        return ToolResult(
            summary=f"verify_finding llm unavailable: {out['error']}",
            raw_output=out,
        )
    if out.get("removed"):
        summary = f"verify_finding {finding_id}: FALSE POSITIVE removed — {out['reasoning']}"
    else:
        summary = (
            f"verify_finding {finding_id}: {out['verdict']} "
            f"→ confidence={out['confidence']} — {out['reasoning']}"
        )
    return ToolResult(findings_added=0, summary=summary, raw_output=out)


# Confidences that warrant an automatic verification pass before reporting.
_UNVERIFIED = {"", "heuristic", "probable", None}


def auto_verify_pending(
    state: Any,
    config: Any,
    pacer: Pacer,
    client: Any | None,
    *,
    limit: int = 12,
) -> dict[str, Any]:
    """Verify every non-confirmed finding before the report is generated.

    Bounded by ``limit`` and the run's cost cap so it cannot run away.
    Returns a tally: {verified, confirmed, downgraded, removed, skipped}.
    """
    cap = float(getattr(config, "llm_agent_max_cost_usd", 0.0) or 0.0)
    tally = {"verified": 0, "confirmed": 0, "downgraded": 0, "removed": 0, "skipped": 0}
    pending = [
        f
        for f in list(getattr(state, "findings", None) or [])
        if str(getattr(f, "confidence", "") or "") in {"heuristic", "probable"}
    ]
    for finding in pending[: max(0, int(limit))]:
        if cap and float(getattr(config, "_llm_cost_usd", 0.0) or 0.0) > cap:
            tally["skipped"] += 1
            continue
        out = _verify_one(finding, state, config, pacer, client)
        if out.get("error"):
            tally["skipped"] += 1
            continue
        tally["verified"] += 1
        if out.get("removed"):
            tally["removed"] += 1
        elif out.get("verdict") == "confirmed":
            tally["confirmed"] += 1
        else:
            tally["downgraded"] += 1
    tally["skipped"] += max(0, len(pending) - int(limit))
    return tally


def _workflow_digest(state: Any, limit: int = 60) -> str:
    endpoints = getattr(state, "endpoints", None) or {}
    lines: list[str] = []
    for url, meta in list(endpoints.items())[:limit]:
        meta = meta or {}
        method = str(meta.get("method") or "GET").upper()
        names: list[str] = []
        for item in meta.get("params") or []:
            if isinstance(item, dict):
                nm = str(item.get("name") or item.get("key") or "").strip()
            else:
                nm = str(item).strip()
            if nm:
                names.append(nm)
        path = urlparse(str(url)).path or "/"
        lines.append(f"{method} {path} params={names}")
    return "\n".join(lines) or "(no endpoints)"


def analyze_logic(
    decision: PlannerDecision,
    state: Any,
    config: Any,
) -> ToolResult:
    digest = _workflow_digest(state)
    confirmed = [
        f"{getattr(f, 'id', '')}@{urlparse(str(getattr(f, 'url', ''))).path}"
        for f in (getattr(state, "findings", None) or [])
        if str(getattr(f, "confidence", "")) == "confirmed"
    ][:20]
    user = (
        f"TARGET: {getattr(config, 'target', '')}\n"
        f"CONFIRMED FINDINGS: {confirmed or '(none)'}\n"
        f"ENDPOINTS:\n{digest}\n\n"
        "Infer the workflow and propose concrete business-logic abuse cases. JSON only."
    )
    call = complete_json(_LOGIC_SYSTEM, user, config, use_reasoning=True, max_tokens=1200)
    if call.data is None:
        return ToolResult(
            summary=f"analyze_logic llm unavailable: {call.error}",
            raw_output={"error": call.error},
        )
    raw = call.data.get("hypotheses")
    hyps = [h for h in raw if isinstance(h, dict)] if isinstance(raw, list) else []
    if not hyps:
        return ToolResult(
            summary="analyze_logic produced no hypotheses",
            raw_output={"hypotheses": []},
        )
    store = getattr(state, "hypotheses", None)
    if store is None:
        state.hypotheses = []
        store = state.hypotheses
    queued = 0
    for h in hyps[:15]:
        text = str(h.get("hypothesis") or "").strip()
        if not text:
            continue
        store.append(
            {
                "hypothesis": text,
                "target_url": str(h.get("target_url") or ""),
                "reasoning": str(h.get("reasoning") or ""),
                "severity": str(h.get("severity") or "medium"),
                "source": "analyze_logic",
            }
        )
        queued += 1
    return ToolResult(
        findings_added=0,
        summary=f"analyze_logic queued {queued} business-logic hypotheses",
        raw_output={"hypotheses": hyps[:15], "queued": queued},
    )
