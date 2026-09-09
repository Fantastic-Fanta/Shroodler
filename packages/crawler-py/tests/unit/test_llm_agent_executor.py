from __future__ import annotations

from shroodler.agent import AgentConfig, CrawlAction
from shroodler.llm_agent.executor import execute_tool
from shroodler.llm_agent.planner import PlannerDecision
from shroodler.models import Finding
from shroodler.pacer import Pacer
from shroodler.program import ProgramState, load, save


def _config(**kwargs) -> AgentConfig:
    defaults = {
        "program": "lab",
        "target": "http://127.0.0.1/",
        "llm_agent": True,
        "run_tls_check": False,
        "run_content_discovery": False,
        "run_openapi_discovery": False,
        "run_openapi_probes": False,
    }
    defaults.update(kwargs)
    return AgentConfig(**defaults)


def test_execute_crawl_delegates(monkeypatch):
    called = {}

    def fake_crawl(action, state, config, pacer):
        called["urls"] = list(action.urls)
        assert isinstance(action, CrawlAction)
        return {"pages_crawled": 2, "findings_added": 1, "new_endpoints": 3}

    monkeypatch.setattr("shroodler.agent._execute_crawl", fake_crawl)
    state = ProgramState(slug="lab")
    result = execute_tool(
        PlannerDecision(action="crawl", params={"url": "http://127.0.0.1/a"}),
        state,
        _config(),
        None,
        None,
        Pacer(0),
    )
    assert called["urls"] == ["http://127.0.0.1/a"]
    assert result.findings_added == 1
    assert "crawled" in result.summary
    assert result.done is False


def test_execute_probe_sqli_passes_single_param(monkeypatch):
    seen = {}

    def fake_sqli(url, method, params, cookie, client=None, pacer=None):
        seen["url"] = url
        seen["method"] = method
        seen["params"] = params
        return [
            Finding(
                id="sqli-error",
                severity="high",
                category="payload",
                url=url,
                description="error-based",
                confidence="confirmed",
            )
        ]

    monkeypatch.setattr("shroodler.probes.sqli.probe_sqli", fake_sqli)
    state = ProgramState(
        slug="lab",
        endpoints={
            "http://127.0.0.1/search": {
                "method": "GET",
                "params": [{"name": "q", "value": "a"}, {"name": "page", "value": "1"}],
            }
        },
    )
    result = execute_tool(
        PlannerDecision(
            action="probe_sqli",
            params={"url": "http://127.0.0.1/search", "param": "q", "method": "GET"},
        ),
        state,
        _config(),
        None,
        None,
        Pacer(0),
    )
    assert seen["params"] == [{"name": "q", "value": "a", "in": "query"}]
    assert result.findings_added == 1
    assert any(f.id == "sqli-error" for f in state.findings)


def test_execute_hypothesise_appends(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    state = load("lab")
    result = execute_tool(
        PlannerDecision(
            action="hypothesise",
            params={
                "hypothesis": "IDOR on /api/account",
                "target_url": "http://127.0.0.1/api/account/1",
                "reasoning": "sequential ids",
            },
        ),
        state,
        _config(),
        None,
        None,
        Pacer(0),
    )
    assert result.findings_added == 0
    assert result.done is False
    assert state.hypotheses[0]["hypothesis"] == "IDOR on /api/account"
    save(state)
    reloaded = load("lab")
    assert reloaded.hypotheses[0]["target_url"].endswith("/api/account/1")


def test_execute_report_sets_done():
    state = ProgramState(slug="lab")
    result = execute_tool(
        PlannerDecision(action="report", params={}),
        state,
        _config(),
        None,
        None,
        Pacer(0),
    )
    assert result.done is True
    assert "report" in result.summary


def test_fetch_and_read_truncates_and_paces(monkeypatch):
    paced = {"n": 0}

    class _Pacer:
        def wait(self):
            paced["n"] += 1

    class _Resp:
        status_code = 200
        text = "x" * 5000
        content = b"x" * 5000

    def fake_request(method, url, **kwargs):
        assert method == "GET"
        return _Resp()

    monkeypatch.setattr("shroodler.llm_agent.executor.request", fake_request)
    result = execute_tool(
        PlannerDecision(
            action="fetch_and_read",
            params={"url": "http://127.0.0.1/", "method": "GET"},
        ),
        ProgramState(slug="lab"),
        _config(),
        None,
        None,
        _Pacer(),
    )
    assert result.findings_added == 0
    assert len(result.raw_output["body"]) == 2000


def test_check_authz_calls_run_authz_diff(monkeypatch):
    called = {}

    def fake_diff(urls, **kwargs):
        called["urls"] = list(urls)
        return {
            "findings": [
                Finding(
                    id="authz-broken-access-control",
                    severity="high",
                    category="auth",
                    url=urls[0],
                    description="peer 200",
                    confidence="confirmed",
                )
            ]
        }

    monkeypatch.setattr("shroodler.agent.run_authz_diff", fake_diff)
    state = ProgramState(
        slug="lab",
        endpoints={"http://127.0.0.1/api/1": {"method": "GET"}},
    )
    result = execute_tool(
        PlannerDecision(action="check_authz", params={"url": "http://127.0.0.1/api/1"}),
        state,
        _config(higher_priv_jar="a", lower_priv_jar="b"),
        None,
        None,
        Pacer(0),
    )
    assert called["urls"] == ["http://127.0.0.1/api/1"]
    assert result.findings_added == 1
    assert (state.endpoints["http://127.0.0.1/api/1"].get("tested_authz") is True)


def test_unknown_tool_does_not_http():
    result = execute_tool(
        PlannerDecision(action="drop_db", params={}),
        ProgramState(slug="lab"),
        _config(),
        None,
        None,
        Pacer(0),
    )
    assert result.findings_added == 0
    assert "unknown" in result.summary
