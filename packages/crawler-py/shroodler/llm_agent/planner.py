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

from shroodler.llm_agent.probe_memory import ProbeMemory
from shroodler.llm_agent.tools import tool_by_name
from shroodler.llm_provider import (
    LLMConfig,
    LLMProvider,
    llm_api_key_env,
    llm_complete_sync,
    tools_to_openai,
)
from shroodler.llm_provider import estimate_cost_usd as estimate_cost_usd
from shroodler.llm_triage import _parse_json_object

DEFAULT_MODEL = "claude-sonnet-5"
OPUS_MODEL = "claude-opus-5"
PLANNER_MAX_TOKENS = 512
PLANNER_TEMPERATURE = 0
# ~400 tokens at ~4 chars/token; keep the memory hint small.
_PROBE_MEMORY_MAX_CHARS = 1600
_CONTEXT_MAX_CHARS = 32000  # ~8000 tokens, same budget as build_context

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


def _truncate_names(names: list[str], limit: int) -> list[str]:
    if limit <= 0:
        return []
    out: list[str] = []
    used = 0
    for name in names:
        extra = len(name) + (2 if out else 0)
        if used + extra > limit and out:
            break
        out.append(name)
        used += extra
    return out


def _probe_memory_block(memory: ProbeMemory) -> str:
    """Compact XML hint for Claude. Capped at ~400 tokens."""
    try:
        productive = list(memory.get_productive_probes())
        barren = list(memory.get_barren_probes())
        summary = memory.summary()
    except Exception:  # noqa: BLE001 - planner must never raise
        return ""

    def _render(prod: list[str], barr: list[str]) -> str:
        body = (
            f"{summary}\n"
            f"Productive probes (prioritise these): {prod}\n"
            f"Barren probes (deprioritise these): {barr}\n"
        )
        return "<probe_memory>\n" + body + "</probe_memory>"

    text = _render(productive, barren)
    while len(text) > _PROBE_MEMORY_MAX_CHARS and (productive or barren):
        if len(barren) >= len(productive) and barren:
            barren.pop()
        elif productive:
            productive.pop()
        else:
            break
        text = _render(productive, barren)
    if len(text) > _PROBE_MEMORY_MAX_CHARS:
        budget = max(80, _PROBE_MEMORY_MAX_CHARS - 80)
        productive = _truncate_names(productive, budget // 2)
        barren = _truncate_names(barren, budget // 2)
        text = _render(productive, barren)
    if len(text) > _PROBE_MEMORY_MAX_CHARS:
        text = text[: _PROBE_MEMORY_MAX_CHARS - 16].rstrip() + "\n…[truncated]\n"
    return text


def _with_probe_memory(context: str, memory: ProbeMemory | None) -> str:
    if memory is None:
        return context or ""
    block = _probe_memory_block(memory)
    if not block:
        return context or ""
    text = (context or "").rstrip() + "\n\n" + block + "\n"
    if len(text) > _CONTEXT_MAX_CHARS:
        text = text[: _CONTEXT_MAX_CHARS - 16].rstrip() + "\n…[truncated]\n"
    return text


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


def _provider_for(config: Any) -> LLMProvider:
    raw = str(getattr(config, "llm_provider", "anthropic") or "anthropic")
    try:
        return LLMProvider(raw.strip().lower())
    except ValueError:
        return LLMProvider.ANTHROPIC


def _model_for(config: Any, provider: LLMProvider) -> str:
    raw = str(getattr(config, "llm_agent_model", "") or "").strip()
    if provider is LLMProvider.DEEPSEEK:
        lowered = raw.lower()
        if not raw or lowered in {"sonnet", "opus", "claude-sonnet-5", "claude-opus-5"}:
            return ""
        return raw
    return resolve_llm_agent_model(raw)


def _decision_from_response(response: Any, *, model: str) -> PlannerDecision:
    inp = int(getattr(response, "input_tokens", 0) or 0)
    out = int(getattr(response, "output_tokens", 0) or 0)
    used_model = str(getattr(response, "model", "") or model)
    data = _parse_json_object(getattr(response, "text", "") or "")
    if data is None:
        calls = getattr(response, "tool_calls", None) or []
        if calls:
            first = calls[0] if isinstance(calls[0], dict) else {}
            args = first.get("arguments")
            data = {
                "action": first.get("name"),
                "params": args if isinstance(args, dict) else {},
                "reasoning": "",
            }
    if data is None:
        decision = _fallback("invalid JSON", model=used_model)
        decision.input_tokens = inp
        decision.output_tokens = out
        return decision
    action = data.get("action")
    if not isinstance(action, str) or not action.strip():
        decision = _fallback("missing action", model=used_model)
        decision.input_tokens = inp
        decision.output_tokens = out
        return decision
    action = action.strip()
    if tool_by_name(action) is None:
        decision = _fallback(f"unknown tool {action}", model=used_model)
        decision.input_tokens = inp
        decision.output_tokens = out
        return decision
    params = data.get("params")
    if params is None:
        params = {}
    if not isinstance(params, dict):
        decision = _fallback("params must be an object", model=used_model)
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
        model=used_model,
    )


def plan_next_action(
    context: str,
    tools: list[dict],
    config: Any,
    history: list[Any],
    probe_memory: ProbeMemory | None = None,
) -> PlannerDecision:
    """Ask the configured LLM for the next tool. Never raises; falls back on any failure."""
    provider = _provider_for(config)
    model = _model_for(config, provider)
    if model:
        display_model = model
    elif provider is LLMProvider.DEEPSEEK:
        display_model = "deepseek-chat"
    else:
        display_model = DEFAULT_MODEL
    env_name = llm_api_key_env(provider)
    if not os.environ.get(env_name):
        return _fallback(f"{env_name} missing", model=display_model)
    prompt_context = _with_probe_memory(context, probe_memory)
    try:
        openai_tools = tools_to_openai(tools)
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": _user_prompt(prompt_context, tools, history),
            },
        ]
        llm_config = LLMConfig(
            provider=provider,
            model=model,
            max_tokens=PLANNER_MAX_TOKENS,
            temperature=PLANNER_TEMPERATURE,
        )
        response = llm_complete_sync(messages, llm_config, tools=openai_tools)
        return _decision_from_response(response, model=display_model)
    except Exception as exc:  # noqa: BLE001 - planner must never raise
        _log_error(exc)
        return _fallback(f"{type(exc).__name__}: {exc}", model=display_model)
