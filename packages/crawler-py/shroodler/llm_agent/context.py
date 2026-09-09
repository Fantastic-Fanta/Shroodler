"""Compact engagement context for the opt-in Claude agent."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from shroodler.llm_agent.history import HistoryEntry, trim_history

_SEV_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}
_MAX_FINDINGS = 30
_MAX_ENDPOINTS = 50
_MAX_CHARS = 32000  # ~8000 tokens at ~4 chars/token
_HISTORY_WINDOW = 10


def _as_dict(item: Any) -> dict[str, Any]:
    if item is None:
        return {}
    if isinstance(item, dict):
        return item
    if hasattr(item, "model_dump"):
        try:
            return dict(item.model_dump(exclude_none=True))
        except Exception:  # noqa: BLE001
            pass
    out: dict[str, Any] = {}
    for key in ("id", "url", "severity", "description", "confidence", "category"):
        if hasattr(item, key):
            out[key] = getattr(item, key)
    return out


def _param_names(meta: dict | None) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for item in (meta or {}).get("params") or []:
        if isinstance(item, dict):
            name = str(item.get("name") or item.get("key") or "").strip()
        else:
            name = str(item).strip()
        if name and name not in seen:
            seen.add(name)
            names.append(name)
    return names


def _path_of(url: str) -> str:
    try:
        parsed = urlparse(url)
    except Exception:  # noqa: BLE001
        return url
    path = parsed.path or "/"
    if parsed.query:
        return f"{path}?{parsed.query}"
    return path


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


def _entry_summary(item: Any) -> str:
    if isinstance(item, HistoryEntry):
        return str(item.summary or "")
    if isinstance(item, dict):
        return str(item.get("summary") or "")
    return str(getattr(item, "summary", "") or "")


def _entry_findings(item: Any) -> int:
    if isinstance(item, HistoryEntry):
        return int(item.findings_added or 0)
    if isinstance(item, dict):
        try:
            return int(item.get("findings_added") or 0)
        except (TypeError, ValueError):
            return 0
    try:
        return int(getattr(item, "findings_added", 0) or 0)
    except (TypeError, ValueError):
        return 0


def _confirmed(findings: list[Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw in findings or []:
        row = _as_dict(raw)
        if str(row.get("confidence") or "") != "confirmed":
            continue
        rows.append(row)
    rows.sort(
        key=lambda r: (
            _SEV_RANK.get(str(r.get("severity") or "").lower(), 9),
            str(r.get("id") or ""),
        )
    )
    return rows[:_MAX_FINDINGS]


def _endpoint_rows(state: Any) -> tuple[list[str], list[str], int]:
    endpoints = getattr(state, "endpoints", None) or {}
    untested: list[tuple[int, str]] = []
    tested: list[tuple[int, str]] = []
    for index, (url, meta) in enumerate(endpoints.items()):
        meta = meta or {}
        names = _param_names(meta)
        method = str(meta.get("method") or "GET").upper() or "GET"
        flags = []
        payload_done = bool(meta.get("tested_payload"))
        authz_done = bool(meta.get("tested_authz"))
        if payload_done:
            flags.append("payload")
        if authz_done:
            flags.append("authz")
        line = f"- {method} {_path_of(str(url))} — params: [{', '.join(names)}]"
        if flags:
            line += f" (tested: {','.join(flags)})"
        rank = 0 if not payload_done else 1
        bucket = untested if not payload_done else tested
        bucket.append((index, line))
    ordered = untested + tested
    lines = [line for _, line in ordered[:_MAX_ENDPOINTS]]
    untested_n = len(untested)
    return lines, [line for _, line in untested[:_MAX_ENDPOINTS]], untested_n


def _tested_combos(history: list[Any]) -> list[str]:
    lines: list[str] = []
    seen: set[tuple[str, str, str]] = set()
    for item in history or []:
        action = _entry_action(item)
        params = _entry_params(item)
        url = str(params.get("url") or params.get("target_url") or "")
        param = str(params.get("param") or "")
        key = (action, url, param)
        if not action or key in seen:
            continue
        seen.add(key)
        bit = action
        if url:
            bit += f" {_path_of(url)}"
        if param:
            bit += f" param={param}"
        lines.append(f"- {bit}")
    return lines[-40:]


def _hypotheses(state: Any) -> list[str]:
    rows = getattr(state, "hypotheses", None) or []
    lines: list[str] = []
    for item in rows[-15:]:
        if isinstance(item, dict):
            text = str(item.get("hypothesis") or item.get("text") or "").strip()
            url = str(item.get("target_url") or item.get("url") or "").strip()
        else:
            text = str(item).strip()
            url = ""
        if not text:
            continue
        if url:
            lines.append(f"- {text} ({_path_of(url)})")
        else:
            lines.append(f"- {text}")
    return lines


def _last_action(history: list[Any]) -> str:
    if not history:
        return "(none)"
    item = history[-1]
    action = _entry_action(item)
    params = _entry_params(item)
    url = str(params.get("url") or "")
    param = str(params.get("param") or "")
    summary = _entry_summary(item)
    added = _entry_findings(item)
    bits = [action or "unknown"]
    if url:
        bits.append(f"on {_path_of(url)}")
    if param:
        bits.append(f"param={param}")
    bits.append(f"→ {summary or f'findings_added={added}'}")
    return " ".join(bits)


def build_context(
    state: Any,
    findings: list[Any],
    history: list[Any],
    config: Any,
) -> str:
    """Structured text under ~8000 tokens for the planner."""
    target = str(getattr(config, "target", "") or "")
    slug = str(getattr(state, "slug", "") or getattr(config, "program", "") or "")
    iteration = int(getattr(config, "_iteration", 0) or 0)
    max_iter = int(getattr(config, "max_iterations", 0) or 0)
    window = trim_history(list(history or []), _HISTORY_WINDOW)
    confirmed = _confirmed(findings if findings is not None else getattr(state, "findings", []))
    endpoint_lines, _untested_only, untested_n = _endpoint_rows(state)
    total_endpoints = len(getattr(state, "endpoints", None) or {})

    blocks: list[str] = [
        f"TARGET: {target} (program: {slug})",
        f"ITERATION: {iteration}/{max_iter}",
        "",
        f"CONFIRMED FINDINGS ({len(confirmed)}):",
    ]
    if confirmed:
        for row in confirmed:
            sev = str(row.get("severity") or "info").upper()
            fid = str(row.get("id") or "")
            url = _path_of(str(row.get("url") or ""))
            desc = " ".join(str(row.get("description") or "").split())[:160]
            blocks.append(f"- [{sev}] {fid} @ {url} — {desc}")
    else:
        blocks.append("- (none)")

    blocks.append("")
    blocks.append(f"UNTESTED ENDPOINTS ({untested_n} of {total_endpoints}):")
    if endpoint_lines:
        blocks.extend(endpoint_lines)
    else:
        blocks.append("- (none)")

    combos = _tested_combos(window)
    blocks.append("")
    blocks.append("ALREADY TESTED:")
    if combos:
        blocks.extend(combos)
    else:
        blocks.append("- (none this run)")

    blocks.append("")
    blocks.append(f"LAST ACTION: {_last_action(window)}")

    hyps = _hypotheses(state)
    blocks.append("")
    blocks.append("PENDING HYPOTHESES:")
    if hyps:
        blocks.extend(hyps)
    else:
        blocks.append("- (none)")

    reason = str(getattr(config, "_llm_last_guardrail", "") or "").strip()
    if reason:
        blocks.append("")
        blocks.append(f"GUARDRAIL (previous iteration): {reason}")
        blocks.append("Do not repeat the blocked action; pick a different tool or target.")

    text = "\n".join(blocks).strip() + "\n"
    if len(text) > _MAX_CHARS:
        text = text[: _MAX_CHARS - 20].rstrip() + "\n…[truncated]\n"
    return text
