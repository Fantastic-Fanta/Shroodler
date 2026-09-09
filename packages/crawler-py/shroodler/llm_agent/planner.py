"""Claude planner for the opt-in LLM agent loop.

Fail-closed: invalid JSON, unknown tools, missing key, or SDK errors
return a fallback sentinel (action=None) so the caller uses
``decide_next_action`` for that iteration.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from typing import Any

from shroodler.llm_agent.tools import tool_by_name
from shroodler.llm_triage import _parse_json_object

DEFAULT_MODEL = "claude-sonnet-5"
OPUS_MODEL = "claude-opus-5"
PLANNER_MAX_TOKENS = 512
PLANNER_TEMPERATURE = 0

# Documented Anthropic list prices (USD per million tokens).
# Sonnet 4 / 4.5 / 5 class: $3 input / $15 output.
# Opus 4 / 4.5 / 5 class: $15 input / $75 output.
# Source: Anthropic API pricing pages (2025–2026).
SONNET_INPUT_USD_PER_MTOK = 3.0
SONNET_OUTPUT_USD_PER_MTOK = 15.0
OPUS_INPUT_USD_PER_MTOK = 15.0
OPUS_OUTPUT_USD_PER_MTOK = 75.0

SYSTEM_PROMPT = """You are an expert penetration tester running an authorized security assessment.
Your goal is to find confirmed, high-severity vulnerabilities efficiently.

Guidelines:
- Prioritise confirmed findings over tentative ones
- When you find a vulnerability, immediately think about what it chains with
- If XSS is found: check if session cookies are accessible (no HttpOnly)
- If IDOR is found: check if the same pattern exists on related endpoints
- If SQLi is found: try to extract sensitive data to confirm impact
- If a finding is HIGH or CRITICAL: generate a follow-up hypothesis before moving on
- If the last 3 actions found nothing: change strategy — try a different endpoint or probe type
- Avoid re-testing (url, param, probe_type) combos already in the tested list
- Call report() only when you've exhausted interesting surface or hit the iteration limit

Respond with valid JSON only:
{
  "action": "<tool name from the tools list>",
  "params": {<tool params>},
  "reasoning": "<one sentence: why this action, what you expect to find>"
}"""


@dataclass
class PlannerDecision:
    action: str | None = None
    params: dict[str, Any] = field(default_factory=dict)
    reasoning: str = ""
    fallback: bool = False
    fallback_reason: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    model: str = DEFAULT_MODEL


def resolve_llm_agent_model(name: str | None) -> str:
    """Map CLI aliases onto the models this loop is allowed to call."""
    raw = str(name or "").strip()
    lowered = raw.lower()
    if lowered in {"", "sonnet", "claude-sonnet-5"}:
        return DEFAULT_MODEL
    if lowered in {"opus", "claude-opus-5"}:
        return OPUS_MODEL
    return raw


def prices_for_model(model: str) -> tuple[float, float]:
    """Return (input_usd_per_mtok, output_usd_per_mtok) for `model`."""
    lowered = str(model or "").lower()
    if "opus" in lowered:
        return OPUS_INPUT_USD_PER_MTOK, OPUS_OUTPUT_USD_PER_MTOK
    return SONNET_INPUT_USD_PER_MTOK, SONNET_OUTPUT_USD_PER_MTOK


def estimate_cost_usd(model: str, input_tokens: int, output_tokens: int) -> float:
    inp, out = prices_for_model(model)
    return (max(0, int(input_tokens)) / 1_000_000.0) * inp + (
        max(0, int(output_tokens)) / 1_000_000.0
    ) * out


def _fallback(reason: str, *, model: str = DEFAULT_MODEL) -> PlannerDecision:
    return PlannerDecision(
        action=None,
        params={},
        reasoning="",
        fallback=True,
        fallback_reason=reason,
        model=model,
    )


def _log_error(exc: BaseException) -> None:
    print(
        json.dumps({"error": f"llm_agent: {type(exc).__name__}: {exc}"}, default=str),
        file=sys.stderr,
        flush=True,
    )


def _usage_tokens(message: Any) -> tuple[int, int]:
    usage = getattr(message, "usage", None)
    if usage is None:
        return 0, 0
    try:
        inp = int(getattr(usage, "input_tokens", 0) or 0)
    except (TypeError, ValueError):
        inp = 0
    try:
        out = int(getattr(usage, "output_tokens", 0) or 0)
    except (TypeError, ValueError):
        out = 0
    return max(0, inp), max(0, out)


def _message_text(message: Any) -> str:
    content = getattr(message, "content", None) or []
    bits: list[str] = []
    for block in content:
        text = getattr(block, "text", None)
        if text:
            bits.append(str(text))
    return "\n".join(bits)


def _user_prompt(context: str, tools: list[dict], history: list[Any]) -> str:
    payload = {
        "tools": tools,
        "recent_history": [
            {
                "iteration": getattr(item, "iteration", None)
                if not isinstance(item, dict)
                else item.get("iteration"),
                "action": getattr(item, "action", None)
                if not isinstance(item, dict)
                else item.get("action"),
                "findings_added": getattr(item, "findings_added", 0)
                if not isinstance(item, dict)
                else item.get("findings_added", 0),
                "summary": getattr(item, "summary", "")
                if not isinstance(item, dict)
                else item.get("summary", ""),
            }
            for item in (history or [])[-10:]
        ],
    }
    return (
        (context or "").strip()
        + "\n\nAVAILABLE TOOLS:\n"
        + json.dumps(tools, default=str)
        + "\n\nRECENT HISTORY:\n"
        + json.dumps(payload["recent_history"], default=str)
        + "\n\nRespond with JSON only."
    )


def plan_next_action(
    context: str,
    tools: list[dict],
    config: Any,
    history: list[Any],
) -> PlannerDecision:
    """Ask Claude for the next tool. Never raises; falls back on any failure."""
    model = resolve_llm_agent_model(getattr(config, "llm_agent_model", None))
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return _fallback("ANTHROPIC_API_KEY missing", model=model)
    try:
        import anthropic

        client = anthropic.Anthropic()
        message = client.messages.create(
            model=model,
            max_tokens=PLANNER_MAX_TOKENS,
            temperature=PLANNER_TEMPERATURE,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": _user_prompt(context, tools, history)}],
        )
        inp, out = _usage_tokens(message)
        data = _parse_json_object(_message_text(message))
        if data is None:
            decision = _fallback("invalid JSON", model=model)
            decision.input_tokens = inp
            decision.output_tokens = out
            return decision
        action = data.get("action")
        if not isinstance(action, str) or not action.strip():
            decision = _fallback("missing action", model=model)
            decision.input_tokens = inp
            decision.output_tokens = out
            return decision
        action = action.strip()
        if tool_by_name(action) is None:
            decision = _fallback(f"unknown tool {action}", model=model)
            decision.input_tokens = inp
            decision.output_tokens = out
            return decision
        params = data.get("params")
        if params is None:
            params = {}
        if not isinstance(params, dict):
            decision = _fallback("params must be an object", model=model)
            decision.input_tokens = inp
            decision.output_tokens = out
            return decision
        reasoning = " ".join(str(data.get("reasoning") or "").split())
        return PlannerDecision(
            action=action,
            params=dict(params),
            reasoning=reasoning,
            fallback=False,
            input_tokens=inp,
            output_tokens=out,
            model=model,
        )
    except Exception as exc:  # noqa: BLE001 - planner must never raise
        _log_error(exc)
        return _fallback(f"{type(exc).__name__}: {exc}", model=model)
