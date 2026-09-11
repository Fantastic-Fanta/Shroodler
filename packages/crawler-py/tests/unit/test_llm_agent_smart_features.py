"""Tests for cross-engagement memory, auto-verify, and hypothesis chaining."""

from __future__ import annotations

from types import SimpleNamespace

from shroodler.agent import AgentConfig
from shroodler.llm_agent import engagement_memory as em
from shroodler.llm_agent import hypotheses as hyp
from shroodler.llm_agent import llm_call, payloads
from shroodler.llm_agent.context import build_context
from shroodler.llm_agent.executor import ToolResult
from shroodler.llm_agent.planner import PlannerDecision
from shroodler.models import Finding
from shroodler.pacer import Pacer


def _finding(fid="a", conf="heuristic"):
    return Finding(
        id=fid, severity="high", category="payload",
        url=f"http://127.0.0.1/{fid}", description="d", evidence="e", confidence=conf,
    )


# --- cross-engagement memory -------------------------------------------------


def test_record_fact_and_reinforce():
    st = SimpleNamespace(engagement_memory={})
    em.record_fact(st, "waf_vendor", "Cloudflare", source="waf")
    em.record_fact(st, "waf_vendor", "Cloudflare", source="waf")
    facts = em.get_facts(st)
    assert facts["waf_vendor"]["value"] == "Cloudflare"
    assert facts["waf_vendor"]["runs"] == 2


def test_record_fact_ignores_empty():
    st = SimpleNamespace(engagement_memory={})
    em.record_fact(st, "", "x")
    em.record_fact(st, "k", "")
    assert em.get_facts(st) == {}


def test_snapshot_captures_waf_and_id_scheme():
    st = SimpleNamespace(engagement_memory={}, findings=[], waf_vendor="Akamai", waf_detected=True)

    class PM:
        def endpoint_patterns(self):
            return ["/api/users/{id}", "/api/orders/{id}", "/x/{uuid}"]

    em.snapshot(st, SimpleNamespace(), PM())
    facts = em.get_facts(st)
    assert facts["waf_vendor"]["value"] == "Akamai"
    assert facts["id_scheme"]["value"] == "sequential-integer"


def test_summarize_and_context_surface_facts():
    st = SimpleNamespace(engagement_memory={}, findings=[], endpoints={}, slug="lab", hypotheses=[])
    em.record_fact(st, "jwt_alg", "HS256", source="decode_token")
    block = em.summarize_facts(st)
    assert "KNOWN FACTS" in block and "HS256" in block
    ctx = build_context(st, [], [], SimpleNamespace(target="http://t", max_iterations=10))
    assert "KNOWN FACTS" in ctx and "HS256" in ctx


def test_summarize_empty_is_blank():
    st = SimpleNamespace(engagement_memory={})
    assert em.summarize_facts(st) == ""


# --- auto-verify before report ----------------------------------------------


def _cfg():
    return AgentConfig(program="lab", target="http://127.0.0.1/")


def test_auto_verify_confirms_and_removes(monkeypatch):
    good, bad = _finding("g", "heuristic"), _finding("b", "probable")
    st = SimpleNamespace(findings=[good, bad])
    verdicts = iter([
        llm_call.LlmJson(
            data={"verdict": "confirmed", "confidence": "confirmed", "reasoning": "r"}
        ),
        llm_call.LlmJson(data={"verdict": "false_positive", "reasoning": "benign"}),
    ])
    monkeypatch.setattr(payloads, "_auth", lambda c: ("", ""))
    monkeypatch.setattr(payloads, "request", lambda *a, **k: None)
    monkeypatch.setattr(payloads, "complete_json", lambda *a, **k: next(verdicts))
    tally = payloads.auto_verify_pending(st, _cfg(), Pacer(0.0), None)
    assert tally["confirmed"] == 1
    assert tally["removed"] == 1
    assert [f.id for f in st.findings] == ["g"]
    assert good.confidence == "confirmed"


def test_auto_verify_skips_confirmed_findings(monkeypatch):
    st = SimpleNamespace(findings=[_finding("c", "confirmed")])
    called = {"n": 0}

    def boom(*a, **k):
        called["n"] += 1
        return llm_call.LlmJson(data={"verdict": "confirmed"})

    monkeypatch.setattr(payloads, "_auth", lambda c: ("", ""))
    monkeypatch.setattr(payloads, "request", lambda *a, **k: None)
    monkeypatch.setattr(payloads, "complete_json", boom)
    tally = payloads.auto_verify_pending(st, _cfg(), Pacer(0.0), None)
    assert tally["verified"] == 0
    assert called["n"] == 0


def test_auto_verify_respects_cost_cap(monkeypatch):
    cfg = _cfg()
    cfg.llm_agent_max_cost_usd = 1.0
    cfg._llm_cost_usd = 5.0  # already over cap
    st = SimpleNamespace(findings=[_finding("x", "heuristic")])
    monkeypatch.setattr(payloads, "_auth", lambda c: ("", ""))
    monkeypatch.setattr(payloads, "request", lambda *a, **k: None)
    def _boom(*a, **k):
        raise AssertionError("must not call")

    monkeypatch.setattr(payloads, "complete_json", _boom)
    tally = payloads.auto_verify_pending(st, cfg, Pacer(0.0), None)
    assert tally["verified"] == 0
    assert tally["skipped"] >= 1


# --- hypothesis chaining -----------------------------------------------------


def _scope_open(monkeypatch):
    import shroodler.llm_agent.guardrails as g

    monkeypatch.setattr(g, "load_scope", lambda *a, **k: {})
    monkeypatch.setattr(g, "in_scope", lambda u, s: True)


def _run_hyp(st):
    return hyp.test_hypothesis(
        PlannerDecision(action="test_hypothesis", params={}), st, _cfg(), Pacer(0.0), None
    )


def test_test_hypothesis_validates_on_signal(monkeypatch):
    st = SimpleNamespace(
        hypotheses=[
            {"hypothesis": "xss on q", "target_url": "http://127.0.0.1/s", "reasoning": "r"}
        ],
        findings=[], endpoints={}, slug="lab",
    )
    _scope_open(monkeypatch)
    monkeypatch.setattr(
        hyp, "complete_json",
        lambda *a, **k: llm_call.LlmJson(
            data={"tool": "send_request", "params": {"url": "http://127.0.0.1/s"}}
        ),
    )
    monkeypatch.setattr(
        hyp, "execute_tool",
        lambda *a, **k: ToolResult(
            summary="reflected", raw_output={"reflected": {"INJ": "script"}}
        ),
    )
    r = _run_hyp(st)
    assert r.raw_output["status"] == "validated"
    assert st.hypotheses[0]["status"] == "validated"


def test_test_hypothesis_no_pending():
    st = SimpleNamespace(
        hypotheses=[{"hypothesis": "x", "status": "validated"}], findings=[], endpoints={}
    )
    r = _run_hyp(st)
    assert "no pending" in r.summary


def test_test_hypothesis_rejects_out_of_scope(monkeypatch):
    st = SimpleNamespace(
        hypotheses=[{"hypothesis": "hit evil", "target_url": "http://evil/x"}],
        findings=[], endpoints={}, slug="lab",
    )
    import shroodler.llm_agent.guardrails as g

    monkeypatch.setattr(g, "load_scope", lambda *a, **k: {"allow": ["127.0.0.1"]})
    monkeypatch.setattr(g, "in_scope", lambda u, s: "127.0.0.1" in u)
    monkeypatch.setattr(
        hyp, "complete_json",
        lambda *a, **k: llm_call.LlmJson(data={"tool": "send_request", "params": {"url": "http://evil/x"}}),
    )
    called = {"n": 0}
    monkeypatch.setattr(
        hyp, "execute_tool", lambda *a, **k: called.__setitem__("n", called["n"] + 1)
    )
    r = _run_hyp(st)
    assert "out of scope" in r.summary
    assert called["n"] == 0
    assert st.hypotheses[0]["status"] == "inconclusive"


def test_test_hypothesis_rejects_disallowed_tool(monkeypatch):
    st = SimpleNamespace(
        hypotheses=[{"hypothesis": "x", "target_url": "http://127.0.0.1/s"}],
        findings=[], endpoints={}, slug="lab",
    )
    monkeypatch.setattr(
        hyp, "complete_json",
        lambda *a, **k: llm_call.LlmJson(data={"tool": "rm_rf", "params": {}}),
    )
    r = _run_hyp(st)
    assert "unusable plan" in r.summary
    assert st.hypotheses[0]["status"] == "inconclusive"
