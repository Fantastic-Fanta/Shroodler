from __future__ import annotations

from shroodler.agent import AgentConfig
from shroodler.llm_agent.guardrails import check_guardrails
from shroodler.llm_agent.history import HistoryEntry
from shroodler.llm_agent.planner import PlannerDecision
from shroodler.program import ProgramState


def _config(**kwargs) -> AgentConfig:
    defaults = {
        "program": "lab",
        "target": "http://127.0.0.1/",
        "llm_agent": True,
        "llm_agent_max_cost_usd": 5.0,
    }
    defaults.update(kwargs)
    cfg = AgentConfig(**defaults)
    cfg._llm_cost_usd = 0.0
    return cfg


def _hist(action: str, url: str = "", param: str = "") -> HistoryEntry:
    return HistoryEntry(
        iteration=1,
        action=action,
        params={"url": url, "param": param} if url or param else {"url": url},
    )


def test_blocks_repeat_combo_in_last_five():
    decision = PlannerDecision(
        action="probe_xss",
        params={"url": "http://127.0.0.1/search", "param": "q"},
    )
    history = [_hist("probe_xss", "http://127.0.0.1/search", "q")]
    result = check_guardrails(decision, history, ProgramState(slug="lab"), _config())
    assert result.allowed is False
    assert "repeat" in result.reason


def test_allows_same_combo_outside_window():
    decision = PlannerDecision(
        action="probe_xss",
        params={"url": "http://127.0.0.1/search", "param": "q"},
    )
    history = [_hist("probe_xss", "http://127.0.0.1/search", "q")] + [
        _hist("crawl", "http://127.0.0.1/") for _ in range(5)
    ]
    result = check_guardrails(decision, history, ProgramState(slug="lab"), _config())
    assert result.allowed is True


def test_blocks_out_of_scope(monkeypatch):
    monkeypatch.setattr(
        "shroodler.llm_agent.guardrails.load_scope",
        lambda *a, **k: {
            "include": ["example.com"],
            "exclude": [],
            "allow_subdomains": True,
        },
    )
    decision = PlannerDecision(
        action="fetch_and_read",
        params={"url": "http://evil.example/x"},
    )
    result = check_guardrails(decision, [], ProgramState(slug="lab"), _config())
    assert result.allowed is False
    assert "out of scope" in result.reason


def test_empty_scope_allows_url():
    decision = PlannerDecision(
        action="crawl",
        params={"url": "http://127.0.0.1/"},
    )
    result = check_guardrails(decision, [], ProgramState(slug="lab"), _config())
    assert result.allowed is True


def test_blocks_re_read_of_same_url_with_probe_directive():
    url = "http://127.0.0.1/page"
    history = [_hist("fetch_and_read", url)]
    decision = PlannerDecision(action="fetch_and_read", params={"url": url})
    result = check_guardrails(decision, history, ProgramState(slug="lab"), _config())
    assert result.allowed is False
    # One look is enough; the block steers the planner to probe instead.
    assert "already read" in result.reason and "probe" in result.reason


def test_blocks_fetch_and_read_after_recon_budget():
    # Distinct-URL reads spend the recon budget; the next one is blocked.
    history = [_hist("fetch_and_read", f"http://127.0.0.1/p{i}") for i in range(6)]
    decision = PlannerDecision(action="fetch_and_read", params={"url": "http://127.0.0.1/new"})
    result = check_guardrails(decision, history, ProgramState(slug="lab"), _config())
    assert result.allowed is False
    assert "recon budget" in result.reason


def test_allows_fetch_and_read_of_a_different_url():
    history = [_hist("fetch_and_read", "http://127.0.0.1/page")]
    decision = PlannerDecision(
        action="fetch_and_read",
        params={"url": "http://127.0.0.1/other"},
    )
    result = check_guardrails(decision, history, ProgramState(slug="lab"), _config())
    assert result.allowed is True


def test_blocks_when_cost_exceeds_cap():
    cfg = _config(llm_agent_max_cost_usd=5.0)
    cfg._llm_cost_usd = 5.01
    decision = PlannerDecision(action="crawl", params={"url": "http://127.0.0.1/"})
    result = check_guardrails(decision, [], ProgramState(slug="lab"), cfg)
    assert result.allowed is False
    assert "cost cap" in result.reason


def test_report_with_no_url_is_allowed():
    result = check_guardrails(
        PlannerDecision(action="report", params={}),
        [],
        ProgramState(slug="lab"),
        _config(),
    )
    assert result.allowed is True


def test_recon_budget_counts_crawl_and_reads_together():
    # The planner cannot dodge the budget by alternating crawl and fetch_and_read.
    history = [
        _hist("crawl", "http://127.0.0.1/a"),
        _hist("fetch_and_read", "http://127.0.0.1/b"),
        _hist("crawl", "http://127.0.0.1/c"),
        _hist("fetch_and_read", "http://127.0.0.1/d"),
        _hist("crawl", "http://127.0.0.1/e"),
        _hist("fetch_and_read", "http://127.0.0.1/f"),
    ]
    decision = PlannerDecision(action="crawl", params={"url": "http://127.0.0.1/g"})
    result = check_guardrails(decision, history, ProgramState(slug="lab"), _config())
    assert result.allowed is False
    assert "recon budget" in result.reason
