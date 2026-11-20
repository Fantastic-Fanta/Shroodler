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


def test_blocks_logic_action_before_any_recon():
    # analyze_logic with nothing crawled and no known endpoints -> blocked, so
    # the fallback crawls first instead of reasoning about hallucinated URLs.
    decision = PlannerDecision(action="analyze_logic", params={})
    result = check_guardrails(decision, [], ProgramState(slug="lab"), _config())
    assert result.allowed is False
    assert "crawl the target first" in result.reason


def test_blocks_hypothesis_actions_before_recon():
    for action in ("test_hypothesis", "hypothesise", "hypothesize"):
        decision = PlannerDecision(action=action, params={})
        result = check_guardrails(decision, [], ProgramState(slug="lab"), _config())
        assert result.allowed is False, action


def test_allows_logic_action_once_endpoints_are_known():
    decision = PlannerDecision(action="analyze_logic", params={})
    state = ProgramState(slug="lab", endpoints={"http://127.0.0.1/x": {}})
    result = check_guardrails(decision, [], state, _config())
    assert result.allowed is True


def test_allows_logic_action_after_a_crawl_this_run():
    decision = PlannerDecision(action="analyze_logic", params={})
    cfg = _config()
    cfg._crawled_this_run = True
    result = check_guardrails(decision, [], ProgramState(slug="lab"), cfg)
    assert result.allowed is True


def test_blocks_denied_path_by_rules_of_engagement(monkeypatch):
    from shroodler.llm_agent import guardrails as gr

    monkeypatch.setattr(gr, "load_scope", lambda *_a, **_k: {"deny": ["*/payment*"]})
    decision = PlannerDecision(
        action="probe_sqli",
        params={"url": "http://127.0.0.1/payment/charge", "param": "amt"},
    )
    state = ProgramState(slug="lab", endpoints={"http://127.0.0.1/payment/charge": {}})
    result = check_guardrails(decision, [], state, _config())
    assert result.allowed is False
    assert "off-limits" in result.reason


# --- decision provenance (decided_by) --------------------------------------


_XSS = {"url": "http://127.0.0.1/s", "param": "q"}


def test_decided_by_allowed_on_pass():
    decision = PlannerDecision(action="probe_xss", params=dict(_XSS))
    result = check_guardrails(decision, [], ProgramState(slug="lab"), _config())
    assert result.allowed is True
    assert result.decided_by == "allowed"


def test_decided_by_budget_on_cost_cap():
    cfg = _config()
    cfg._llm_cost_usd = 99.0  # over the 5.0 cap
    decision = PlannerDecision(action="probe_xss", params=dict(_XSS))
    result = check_guardrails(decision, [], ProgramState(slug="lab"), cfg)
    assert result.allowed is False
    assert result.decided_by == "budget"


def test_decided_by_loop_guard_on_repeat():
    decision = PlannerDecision(action="probe_xss", params=dict(_XSS))
    history = [_hist("probe_xss", "http://127.0.0.1/s", "q")]
    result = check_guardrails(decision, history, ProgramState(slug="lab"), _config())
    assert result.decided_by == "loop_guard"


def test_decided_by_recon_budget_is_budget():
    reads = [_hist("crawl", f"http://127.0.0.1/{i}") for i in range(6)]
    decision = PlannerDecision(action="crawl", params={"url": "http://127.0.0.1/more"})
    result = check_guardrails(decision, reads, ProgramState(slug="lab"), _config())
    assert result.allowed is False
    assert result.decided_by == "budget"


def test_decided_by_recon_policy_when_no_endpoints():
    decision = PlannerDecision(action="analyze_logic", params={})
    result = check_guardrails(decision, [], ProgramState(slug="lab"), _config())
    assert result.allowed is False
    assert result.decided_by == "recon_policy"


def test_ready_attack_step_keeps_the_planner_on_its_url():
    from shroodler.exploration import note_improvised_intent

    state = ProgramState(slug="lab", endpoints={"http://127.0.0.1/search": {}})
    note_improvised_intent(
        state,
        summary="sqli on search",
        url="http://127.0.0.1/search",
        action="probe_sqli",
    )
    blocked = check_guardrails(
        PlannerDecision(action="fetch_and_read", params={"url": "http://127.0.0.1/admin"}),
        [],
        state,
        _config(),
    )
    assert blocked.allowed is False
    assert "attack list" in blocked.reason
    allowed = check_guardrails(
        PlannerDecision(
            action="probe_sqli",
            params={"url": "http://127.0.0.1/search", "param": "q"},
        ),
        [],
        state,
        _config(),
    )
    assert allowed.allowed is True


def test_fetch_outside_an_open_intent_falls_back():
    state = ProgramState(
        slug="lab",
        endpoints={"http://127.0.0.1/search": {}},
        exploration_nodes=[
            {
                "id": "intent-1",
                "kind": "intent",
                "key": "probe:http://127.0.0.1/search",
                "summary": "probe search",
                "status": "open",
                "urls": ["http://127.0.0.1/search"],
            }
        ],
    )
    decision = PlannerDecision(
        action="fetch_and_read",
        params={"url": "http://127.0.0.1/admin"},
    )
    result = check_guardrails(decision, [], state, _config())
    assert result.allowed is False
    assert "not an open intent" in result.reason
    allowed = check_guardrails(
        PlannerDecision(action="fetch_and_read", params={"url": "http://127.0.0.1/search"}),
        [],
        state,
        _config(),
    )
    assert allowed.allowed is True


def test_decided_by_no_decision_on_fallback():
    decision = PlannerDecision(action="", fallback=True, fallback_reason="bad json")
    result = check_guardrails(decision, [], ProgramState(slug="lab"), _config())
    assert result.decided_by == "no_decision"
