from __future__ import annotations

from shroodler.agent import AgentConfig
from shroodler.llm_agent.context import build_context
from shroodler.llm_agent.history import HistoryEntry
from shroodler.models import Finding
from shroodler.program import ProgramState


def _config(**kwargs) -> AgentConfig:
    defaults = {
        "program": "altoro",
        "target": "http://demo.testfire.net",
        "max_iterations": 20,
    }
    defaults.update(kwargs)
    cfg = AgentConfig(**defaults)
    cfg._iteration = 3
    return cfg


def test_build_context_includes_target_iteration_and_findings():
    state = ProgramState(
        slug="altoro",
        endpoints={
            "http://demo.testfire.net/api/account/1": {
                "method": "GET",
                "params": [{"name": "accountId"}],
                "tested_payload": False,
            },
            "http://demo.testfire.net/search.jsp": {
                "method": "GET",
                "params": [{"name": "query"}],
                "tested_payload": True,
            },
        },
        findings=[
            Finding(
                id="xss-reflected",
                severity="high",
                category="payload",
                url="http://demo.testfire.net/search.jsp?query=",
                description="GET param 'query' reflects payload verbatim",
                confidence="confirmed",
            ),
            Finding(
                id="missing-csp",
                severity="medium",
                category="header",
                url="http://demo.testfire.net",
                description="Content-Security-Policy not set",
                confidence="confirmed",
            ),
        ],
        hypotheses=[
            {
                "hypothesis": "XSS may be stored after login",
                "target_url": "http://demo.testfire.net/search.jsp",
                "reasoning": "cached results",
            }
        ],
    )
    history = [
        HistoryEntry(
            iteration=2,
            action="probe_xss",
            params={"url": "http://demo.testfire.net/search.jsp", "param": "query"},
            findings_added=1,
            summary="found xss-reflected (HIGH)",
        )
    ]
    text = build_context(state, state.findings, history, _config())
    assert "TARGET: http://demo.testfire.net (program: altoro)" in text
    assert "ITERATION: 3/20" in text
    assert "[HIGH] xss-reflected" in text
    assert "[MEDIUM] missing-csp" in text
    assert "UNTESTED ENDPOINTS" in text
    assert "/api/account/1" in text
    assert "LAST ACTION: probe_xss" in text
    assert "XSS may be stored" in text
    assert "ALREADY TESTED:" in text
    section = text.split("UNTESTED ENDPOINTS", 1)[1].split("ALREADY TESTED", 1)[0]
    assert "/api/account/1" in section
    untested_at = section.index("/api/account/1")
    # tested payload endpoint may still appear later in the same list
    if "/search.jsp" in section:
        assert untested_at < section.index("/search.jsp")


def test_build_context_caps_findings_and_endpoints():
    findings = [
        Finding(
            id=f"xss-{i}",
            severity="low" if i else "critical",
            category="payload",
            url=f"http://demo.testfire.net/{i}",
            description="x",
            confidence="confirmed",
        )
        for i in range(40)
    ]
    endpoints = {
        f"http://demo.testfire.net/p/{i}": {
            "method": "GET",
            "params": [{"name": "q"}],
            "tested_payload": False,
        }
        for i in range(80)
    }
    state = ProgramState(slug="altoro", endpoints=endpoints, findings=findings)
    text = build_context(state, findings, [], _config())
    assert text.count("[CRITICAL]") == 1
    assert text.count("[LOW]") == 29
    assert text.count("GET /p/") == 50
    assert len(text) < 32000
