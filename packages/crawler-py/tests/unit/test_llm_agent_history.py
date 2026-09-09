from __future__ import annotations

from shroodler.llm_agent.history import HistoryEntry, trim_history


def test_trim_history_keeps_most_recent():
    items = [
        HistoryEntry(iteration=i, action=f"a{i}", summary=str(i))
        for i in range(15)
    ]
    kept = trim_history(items, 10)
    assert len(kept) == 10
    assert [h.iteration for h in kept] == list(range(5, 15))


def test_trim_history_default_and_empty():
    items = [HistoryEntry(iteration=1, action="crawl")]
    assert trim_history(items, 10) == items
    assert trim_history(items, 0) == []
    assert trim_history([], 10) == []


def test_history_entry_fields():
    entry = HistoryEntry(
        iteration=3,
        action="probe_xss",
        params={"url": "http://x/", "param": "q"},
        reasoning="check search",
        findings_added=1,
        summary="found xss-reflected",
    )
    assert entry.action == "probe_xss"
    assert entry.params["param"] == "q"
    assert entry.findings_added == 1
