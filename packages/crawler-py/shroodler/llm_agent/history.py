"""Rolling action/result window for the opt-in Claude agent."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class HistoryEntry:
    iteration: int
    action: str
    params: dict[str, Any] = field(default_factory=dict)
    reasoning: str = ""
    findings_added: int = 0
    summary: str = ""
    # Trimmed structured result of the last tool (status, timing, reflection,
    # diff, body snippet) so the planner reasons on evidence, not a one-liner.
    observation: dict[str, Any] = field(default_factory=dict)


def trim_history(
    history: list[HistoryEntry],
    max_entries: int = 10,
) -> list[HistoryEntry]:
    """Keep only the most recent entries to stay within context budget."""
    cap = max(0, int(max_entries))
    if cap == 0:
        return []
    return list(history)[-cap:]
