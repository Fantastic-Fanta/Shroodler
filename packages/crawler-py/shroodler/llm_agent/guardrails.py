"""Safety checks for the opt-in Claude agent loop.

Blocked decisions fall back to ``decide_next_action`` for that iteration.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from shroodler.llm_agent.history import HistoryEntry
from shroodler.llm_agent.planner import PlannerDecision
from shroodler.scope import in_scope, load_scope

# Recon actions counted against the budget. Both count, so the planner cannot
# dodge the limit by alternating crawl and fetch_and_read.
_RECON_ACTIONS = {"fetch_and_read", "crawl"}
# Max recon actions per run before the planner is forced to probe.
_MAX_READS = 6


@dataclass
class GuardrailResult:
    allowed: bool
    reason: str = ""


def _entry_action(item: Any) -> str:
    if isinstance(item, HistoryEntry):
        return str(item.action or "")
    if isinstance(item, dict):
        return str(item.get("action") or "")
    return str(getattr(item, "action", "") or "")


def _entry_params(item: Any) -> dict[str, Any]:
    if isinstance(item, HistoryEntry):
        return dict(item.params or {})
    if isinstance(item, dict):
        raw = item.get("params") or {}
        return dict(raw) if isinstance(raw, dict) else {}
    raw = getattr(item, "params", None) or {}
    return dict(raw) if isinstance(raw, dict) else {}


def _combo(action: str, params: dict[str, Any] | None) -> tuple[str, str, str]:
    params = params or {}
    url = str(params.get("url") or params.get("target_url") or "")
    param = str(params.get("param") or "")
    return (str(action or ""), url, param)


def _decision_url(decision: PlannerDecision) -> str:
    params = decision.params or {}
    return str(params.get("url") or params.get("target_url") or "")


def _all_urls(decision: PlannerDecision) -> list[str]:
    """Every target URL a decision would hit, including nested request specs
    (compare_responses a/b), so scope can be enforced on all of them."""
    params = decision.params or {}
    urls: list[str] = []
    top = str(params.get("url") or params.get("target_url") or "")
    if top:
        urls.append(top)
    for key in ("a", "b"):
        spec = params.get(key)
        if isinstance(spec, dict):
            nested = str(spec.get("url") or "")
            if nested:
                urls.append(nested)
    return urls


def check_guardrails(
    decision: PlannerDecision,
    history: list[HistoryEntry],
    state: Any,
    config: Any,
) -> GuardrailResult:
    """Return whether `decision` may run. Never raises."""
    if decision is None or decision.fallback or not decision.action:
        return GuardrailResult(False, decision.fallback_reason if decision else "no decision")

    cost = float(getattr(config, "_llm_cost_usd", 0.0) or 0.0)
    cap = float(getattr(config, "llm_agent_max_cost_usd", 5.0) or 0.0)
    if cost > cap:
        return GuardrailResult(
            False,
            f"cost cap exceeded ({cost:.4f} USD > {cap:.4f} USD)",
        )

    params = decision.params or {}
    url = _decision_url(decision)

    if decision.action in _RECON_ACTIONS:
        recon = [item for item in (history or []) if _entry_action(item) in _RECON_ACTIONS]
        # Never re-read a URL already read this run: one look is enough.
        if decision.action == "fetch_and_read" and url and any(
            _entry_action(i) == "fetch_and_read" and str(_entry_params(i).get("url") or "") == url
            for i in recon
        ):
            return GuardrailResult(
                False,
                f"already read {url} — probe it now (craft_payloads or a probe_ tool), "
                "do not read it again",
            )
        # Hard recon budget across crawl + reads: force a transition to attacking.
        if len(recon) >= _MAX_READS:
            return GuardrailResult(
                False,
                f"recon budget spent ({len(recon)} crawl/read actions) — stop "
                "reconnaissance and probe an untested endpoint with craft_payloads "
                "or a probe_ tool",
            )

    combo = _combo(decision.action, params)
    window = list(history or [])[-5:]
    for item in window:
        if _combo(_entry_action(item), _entry_params(item)) == combo:
            return GuardrailResult(
                False,
                f"repeat (action,url,param) in last 5: {combo[0]} {combo[1]} {combo[2]}",
            )

    candidate_urls = _all_urls(decision)
    if candidate_urls:
        slug = str(getattr(state, "slug", "") or getattr(config, "program", "") or "")
        scope_file = getattr(config, "scope_file", None)
        scope = load_scope(slug, path=scope_file) if slug else {}
        for candidate in candidate_urls:
            if not in_scope(candidate, scope):
                return GuardrailResult(False, f"out of scope: {candidate}")

    return GuardrailResult(True, "")
