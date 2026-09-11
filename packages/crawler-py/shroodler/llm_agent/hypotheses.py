"""Turn queued hypotheses into an auto-validated chain.

``analyze_logic`` and ``hypothesise`` fill ``state.hypotheses`` with ideas.
``test_hypothesis`` closes the loop: it pops the top *pending* hypothesis,
asks the reasoning model to translate it into one concrete tool action,
runs that action under the same scope guardrail as the main loop, and
records the outcome (validated / refuted / inconclusive) back on the
hypothesis so the planner stops re-suggesting it.

Only a safe allowlist of concrete tools can be planned, and the planned
target must pass the scope check, so a hypothesis can never widen scope.
"""

from __future__ import annotations

from typing import Any

from shroodler.llm_agent.executor import ToolResult, execute_tool
from shroodler.llm_agent.llm_call import complete_json
from shroodler.llm_agent.planner import PlannerDecision
from shroodler.pacer import Pacer

# Concrete tools a hypothesis may be translated into. Anything else is refused.
_ALLOWED_TOOLS = {
    "send_request",
    "craft_payloads",
    "replay_as_user",
    "compare_responses",
    "fetch_and_read",
    "probe_sqli",
    "probe_xss",
    "probe_idor",
    "probe_ssrf",
    "check_authz",
}
_TESTED_STATUSES = {"validated", "refuted", "inconclusive"}

_PLAN_SYSTEM = (
    "You are a penetration tester turning a hypothesis into ONE concrete, "
    "in-scope test. Choose exactly one tool from the allowed list and give its "
    "params. Prefer send_request or craft_payloads when you need to probe an "
    "input; replay_as_user or compare_responses for access-control and "
    "tampering. Respond with JSON only: "
    '{"tool": "<one allowed tool>", "params": {...}, "expected_signal": '
    '"what result would confirm the hypothesis"}.'
)


def _pending(state: Any) -> list[tuple[int, dict[str, Any]]]:
    out: list[tuple[int, dict[str, Any]]] = []
    for i, h in enumerate(getattr(state, "hypotheses", None) or []):
        if isinstance(h, dict) and str(h.get("status") or "") not in _TESTED_STATUSES:
            out.append((i, h))
    return out


def _scoped(decision: PlannerDecision, state: Any, config: Any) -> bool:
    try:
        from shroodler.llm_agent.guardrails import check_guardrails

        return check_guardrails(decision, [], state, config).allowed
    except Exception:  # noqa: BLE001 - fail closed: treat as out of scope
        return False


def _classify_outcome(result: ToolResult) -> str:
    """Map a sub-tool result onto validated / inconclusive."""
    raw = result.raw_output if isinstance(result.raw_output, dict) else {}
    if int(result.findings_added or 0) >= 1:
        return "validated"
    if raw.get("access_control_lead"):
        return "validated"
    results = raw.get("results")
    if isinstance(results, list) and any(
        isinstance(r, dict) and r.get("signal") not in (None, "no-signal") for r in results
    ):
        return "validated"
    reflected = raw.get("reflected")
    if isinstance(reflected, dict) and reflected:
        return "validated"
    if raw.get("error"):
        return "inconclusive"
    return "inconclusive"


def test_hypothesis(
    decision: PlannerDecision,
    state: Any,
    config: Any,
    pacer: Pacer,
    owner_client: Any | None,
    probe_memory: Any = None,
) -> ToolResult:
    params = dict(decision.params or {})
    pending = _pending(state)
    if not pending:
        return ToolResult(
            summary="test_hypothesis: no pending hypotheses",
            raw_output={"pending": 0},
        )
    # Optional explicit index; else take the first pending one.
    idx = params.get("index")
    chosen = None
    if isinstance(idx, int) and 0 <= idx < len(getattr(state, "hypotheses", []) or []):
        h = state.hypotheses[idx]
        if isinstance(h, dict):
            chosen = (idx, h)
    if chosen is None:
        chosen = pending[0]
    h_index, hyp = chosen
    text = str(hyp.get("hypothesis") or "")
    target = str(hyp.get("target_url") or "")

    user = (
        f"HYPOTHESIS: {text}\n"
        f"TARGET URL: {target or '(none given)'}\n"
        f"REASONING: {hyp.get('reasoning') or ''}\n"
        f"ALLOWED TOOLS: {sorted(_ALLOWED_TOOLS)}\n\n"
        "Return one concrete test as JSON."
    )
    call = complete_json(_PLAN_SYSTEM, user, config, use_reasoning=True, max_tokens=500)
    if call.data is None:
        return ToolResult(
            summary=f"test_hypothesis: planner unavailable: {call.error}",
            raw_output={"error": call.error},
        )
    tool = str(call.data.get("tool") or "").strip()
    tool_params = call.data.get("params")
    if tool not in _ALLOWED_TOOLS or not isinstance(tool_params, dict):
        _mark(state, h_index, "inconclusive", f"planner returned no usable action ({tool})")
        return ToolResult(
            summary=f"test_hypothesis: unusable plan '{tool}'",
            raw_output={"tool": tool, "status": "inconclusive"},
        )
    sub = PlannerDecision(
        action=tool,
        params=dict(tool_params),
        reasoning=f"test hypothesis: {text}"[:200],
    )
    if not _scoped(sub, state, config):
        _mark(state, h_index, "inconclusive", "planned action was out of scope")
        return ToolResult(
            summary="test_hypothesis: planned action out of scope; skipped",
            raw_output={"tool": tool, "status": "inconclusive", "reason": "out of scope"},
        )
    result = execute_tool(
        sub, state, config, owner_client, None, pacer, probe_memory=probe_memory
    )
    outcome = _classify_outcome(result)
    _mark(state, h_index, outcome, result.summary)
    return ToolResult(
        findings_added=int(result.findings_added or 0),
        summary=f"test_hypothesis [{outcome}] via {tool}: {result.summary}",
        raw_output={
            "hypothesis": text,
            "tool": tool,
            "status": outcome,
            "expected_signal": str(call.data.get("expected_signal") or ""),
            "sub_result": result.raw_output,
        },
    )


def _mark(state: Any, index: int, status: str, note: str) -> None:
    try:
        hyps = getattr(state, "hypotheses", None) or []
        if 0 <= index < len(hyps) and isinstance(hyps[index], dict):
            hyps[index]["status"] = status
            hyps[index]["outcome"] = str(note or "")[:200]
    except Exception:  # noqa: BLE001
        return
