"""Cross-engagement memory for the LLM agent.

Facts learned during one run — the ID scheme, JWT algorithm, WAF vendor,
framework, auth style — are stored on program state and surfaced to the
planner on the next run, so the agent starts a repeat engagement already
knowing the target's shape instead of rediscovering it.

Facts are cheap, structured, and non-secret. Each is stored as
``engagement_memory[key] = {"value", "source", "updated", "runs"}``.
A later observation for the same key overwrites the value and bumps the
run counter, so a fact that keeps reappearing reads as more reliable.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

# Keys we know how to summarise, in the order they should appear.
_KNOWN_KEYS = (
    "waf_vendor",
    "id_scheme",
    "jwt_alg",
    "framework",
    "auth_style",
    "graphql",
)
_MAX_FACTS = 20
_MAX_VALUE_CHARS = 120


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _store(state: Any) -> dict[str, Any]:
    mem = getattr(state, "engagement_memory", None)
    if not isinstance(mem, dict):
        mem = {}
        try:
            state.engagement_memory = mem
        except Exception:  # noqa: BLE001
            return {}
    return mem


def record_fact(state: Any, key: str, value: Any, *, source: str = "") -> None:
    """Store or update one fact. Never raises."""
    try:
        k = str(key or "").strip()
        v = str(value or "").strip()[:_MAX_VALUE_CHARS]
        if not k or not v:
            return
        mem = _store(state)
        if not isinstance(mem, dict):
            return
        prior = mem.get(k) if isinstance(mem.get(k), dict) else {}
        runs = int(prior.get("runs") or 0) + 1
        mem[k] = {
            "value": v,
            "source": source or prior.get("source") or "",
            "updated": _now(),
            "runs": runs,
        }
        # Cap total facts, dropping the least-reinforced first.
        if len(mem) > _MAX_FACTS:
            worst = sorted(mem.items(), key=lambda kv: int((kv[1] or {}).get("runs") or 0))[0][0]
            if worst != k:
                mem.pop(worst, None)
    except Exception:  # noqa: BLE001 - memory must never break the loop
        return


def get_facts(state: Any) -> dict[str, Any]:
    mem = getattr(state, "engagement_memory", None)
    return dict(mem) if isinstance(mem, dict) else {}


def _id_scheme_from_probe_memory(probe_memory: Any) -> str | None:
    """Infer the dominant ID placeholder ({id}/{uuid}/{token}) seen so far."""
    if probe_memory is None:
        return None
    try:
        patterns = probe_memory.endpoint_patterns()
    except Exception:  # noqa: BLE001
        return None
    counts = {"{id}": 0, "{uuid}": 0, "{token}": 0}
    for pat in patterns or []:
        for token in counts:
            if token in str(pat):
                counts[token] += 1
    best = max(counts, key=lambda t: counts[t])
    if counts[best] <= 0:
        return None
    return {"{id}": "sequential-integer", "{uuid}": "uuid", "{token}": "opaque-token"}[best]


def snapshot(state: Any, config: Any, probe_memory: Any = None) -> None:
    """Capture end-of-run fingerprint facts onto engagement memory. Never raises."""
    try:
        vendor = str(getattr(state, "waf_vendor", "") or "").strip()
        if vendor:
            record_fact(state, "waf_vendor", vendor, source="waf_detect")
        elif getattr(state, "waf_detected", False):
            record_fact(state, "waf_vendor", "present (vendor unknown)", source="waf_detect")
        scheme = _id_scheme_from_probe_memory(probe_memory)
        if scheme:
            record_fact(state, "id_scheme", scheme, source="probe_memory")
        # Confirmed GraphQL surface is a durable target-shape fact.
        for f in getattr(state, "findings", None) or []:
            cat = str(getattr(f, "category", "") or "")
            fid = str(getattr(f, "id", "") or "")
            if "graphql" in cat or "graphql" in fid:
                record_fact(state, "graphql", "endpoint present", source="probe")
                break
    except Exception:  # noqa: BLE001
        return


def summarize_facts(state: Any) -> str:
    """Render a compact KNOWN FACTS block for the planner context, or ''."""
    facts = get_facts(state)
    if not facts:
        return ""
    lines: list[str] = ["KNOWN FACTS (carried from prior runs — verify, do not assume):"]
    ordered = [k for k in _KNOWN_KEYS if k in facts] + [
        k for k in sorted(facts) if k not in _KNOWN_KEYS
    ]
    for key in ordered:
        row = facts.get(key) or {}
        val = str(row.get("value") or "")
        runs = int(row.get("runs") or 0)
        seen = f" (seen in {runs} runs)" if runs > 1 else ""
        lines.append(f"- {key}: {val}{seen}")
    return "\n".join(lines)
