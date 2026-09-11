"""Tests for the smarter LLM agent tools: deeper HTTP primitives, adaptive
payloads, evidence-based verification, business-logic reasoning, richer
feedback, and the DeepSeek-by-default cost profile."""

from __future__ import annotations

import base64
import json
from types import SimpleNamespace

import pytest

from shroodler.agent import AgentConfig
from shroodler.llm_agent import http_tools, llm_call, payloads
from shroodler.llm_agent.context import trim_observation
from shroodler.llm_agent.executor import execute_tool
from shroodler.llm_agent.guardrails import _all_urls, check_guardrails
from shroodler.llm_agent.planner import PlannerDecision
from shroodler.models import Finding
from shroodler.pacer import Pacer


def _decision(action: str, **params) -> PlannerDecision:
    return PlannerDecision(action=action, params=dict(params))


def _b64json(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


# --- reflection_context ------------------------------------------------------


@pytest.mark.parametrize(
    "body,needle,expected",
    [
        ('<script>var a="MARK";</script>', "MARK", "script"),
        ('<input value="MARK">', "MARK", "attribute"),
        ("<p>MARK</p>", "MARK", "text"),
        ('{"x":"MARK"}', "MARK", "json"),
        ("<!-- MARK -->", "MARK", "comment"),
        ("nothing here", "MARK", "none"),
    ],
)
def test_reflection_context(body, needle, expected):
    assert http_tools.reflection_context(body, needle) == expected


# --- decode_token (no network) ----------------------------------------------


def test_decode_token_flags_alg_none():
    tok = f"{_b64json({'alg': 'none'})}.{_b64json({'sub': '1'})}."
    result = http_tools.decode_token(_decision("decode_token", token=tok))
    assert result.raw_output["kind"] == "jwt"
    assert "alg:none" in result.raw_output["weak_signals"]


def test_decode_token_flags_hmac():
    tok = f"{_b64json({'alg': 'HS256'})}.{_b64json({'sub': '1'})}.sig"
    result = http_tools.decode_token(_decision("decode_token", token=tok))
    assert any("HMAC" in s for s in result.raw_output["weak_signals"])
    assert result.raw_output["signature_present"] is True


def test_decode_token_base64_fallback():
    tok = base64.urlsafe_b64encode(b"hello").decode()
    result = http_tools.decode_token(_decision("decode_token", token=tok))
    assert result.raw_output["kind"] == "base64"
    assert result.raw_output["decoded"] == "hello"


def test_decode_token_missing():
    result = http_tools.decode_token(_decision("decode_token"))
    assert "missing token" in result.summary


def test_execute_tool_routes_decode_token():
    tok = f"{_b64json({'alg': 'none'})}.{_b64json({'a': 1})}."
    result = execute_tool(
        _decision("decode_token", token=tok),
        SimpleNamespace(endpoints={}, findings=[]),
        AgentConfig(program="lab", target="http://127.0.0.1/"),
        None,
        None,
        Pacer(0.0),
    )
    assert result.raw_output.get("kind") == "jwt"


# --- richer feedback: trim_observation --------------------------------------


def test_trim_observation_keeps_evidence_and_caps_body():
    raw = {
        "status_code": 200,
        "elapsed_s": 4.1,
        "reflected": {"x": "script"},
        "verdict": "confirmed",
        "body": "B" * 5000,
        "results": [
            {"payload": "a", "signal": "no-signal"},
            {"payload": "b", "signal": "sql-error-reflected"},
        ],
    }
    trimmed = trim_observation(raw)
    assert trimmed["status_code"] == 200
    assert trimmed["verdict"] == "confirmed"
    assert len(trimmed["body"]) == 600
    # Only the signal-bearing payload row is kept.
    assert trimmed["payload_hits"] == [{"payload": "b", "signal": "sql-error-reflected"}]


def test_trim_observation_ignores_non_dict():
    assert trim_observation("nope") == {}
    assert trim_observation(None) == {}


# --- guardrails: scope covers nested request specs --------------------------


def test_all_urls_collects_nested_specs():
    decision = _decision(
        "compare_responses",
        a={"url": "http://127.0.0.1/a"},
        b={"url": "http://evil.example/b"},
    )
    assert _all_urls(decision) == ["http://127.0.0.1/a", "http://evil.example/b"]


def test_guardrail_blocks_out_of_scope_nested_url(monkeypatch):
    monkeypatch.setattr(
        "shroodler.llm_agent.guardrails.load_scope",
        lambda *a, **k: {"allow": ["127.0.0.1"]},
    )
    monkeypatch.setattr(
        "shroodler.llm_agent.guardrails.in_scope",
        lambda url, scope: "127.0.0.1" in url,
    )
    config = AgentConfig(program="lab", target="http://127.0.0.1/")
    decision = _decision(
        "compare_responses",
        a={"url": "http://127.0.0.1/a"},
        b={"url": "http://evil.example/b"},
    )
    result = check_guardrails(decision, [], SimpleNamespace(slug="lab"), config)
    assert result.allowed is False
    assert "out of scope" in result.reason
    assert "evil.example" in result.reason


# --- fail-closed LLM tools without a key ------------------------------------


def test_craft_payloads_fails_closed_without_key(monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    config = AgentConfig(program="lab", target="http://127.0.0.1/")
    result = payloads.craft_payloads(
        _decision("craft_payloads", url="http://127.0.0.1/", param="q", vuln_class="sqli"),
        SimpleNamespace(endpoints={}, findings=[]),
        config,
        Pacer(0.0),
        None,
    )
    assert result.findings_added == 0
    assert "unavailable" in result.summary or "missing" in result.raw_output.get("error", "")


def test_analyze_logic_fails_closed_without_key(monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    config = AgentConfig(program="lab", target="http://127.0.0.1/")
    result = payloads.analyze_logic(
        _decision("analyze_logic"),
        SimpleNamespace(endpoints={}, findings=[], target="http://127.0.0.1/"),
        config,
    )
    assert result.findings_added == 0
    assert "error" in result.raw_output


# --- verify_finding removes false positives, keeps confirmed -----------------


def _finding(fid="x", conf="heuristic"):
    return Finding(
        id=fid,
        severity="medium",
        category="payload",
        url="http://127.0.0.1/p",
        description="reflected value",
        evidence="param=q payload=<x>",
        confidence=conf,
    )


def test_verify_finding_drops_false_positive(monkeypatch):
    state = SimpleNamespace(findings=[_finding()], endpoints={})
    config = AgentConfig(program="lab", target="http://127.0.0.1/")

    monkeypatch.setattr(
        "shroodler.llm_agent.payloads.request",
        lambda *a, **k: None,
    )
    monkeypatch.setattr(
        "shroodler.llm_agent.payloads.complete_json",
        lambda *a, **k: llm_call.LlmJson(
            data={"verdict": "false_positive", "reasoning": "benign reflection"}
        ),
    )
    result = payloads.verify_finding(
        _decision("verify_finding", finding_id="x"), state, config, Pacer(0.0), None
    )
    assert result.raw_output["verdict"] == "false_positive"
    assert result.raw_output["removed"] is True
    assert state.findings == []


def test_verify_finding_confirms_and_stamps(monkeypatch):
    f = _finding(conf="heuristic")
    state = SimpleNamespace(findings=[f], endpoints={})
    config = AgentConfig(program="lab", target="http://127.0.0.1/")
    monkeypatch.setattr("shroodler.llm_agent.payloads.request", lambda *a, **k: None)
    monkeypatch.setattr(
        "shroodler.llm_agent.payloads.complete_json",
        lambda *a, **k: llm_call.LlmJson(
            data={"verdict": "confirmed", "confidence": "confirmed", "reasoning": "real"}
        ),
    )
    result = payloads.verify_finding(
        _decision("verify_finding", finding_id="x"), state, config, Pacer(0.0), None
    )
    assert result.raw_output["verdict"] == "confirmed"
    assert state.findings[0].confidence == "confirmed"


def test_verify_finding_unknown_id():
    state = SimpleNamespace(findings=[], endpoints={})
    config = AgentConfig(program="lab", target="http://127.0.0.1/")
    result = payloads.verify_finding(
        _decision("verify_finding", finding_id="nope"), state, config, Pacer(0.0), None
    )
    assert "no finding" in result.summary


# --- analyze_logic queues hypotheses onto state -----------------------------


def test_analyze_logic_queues_hypotheses(monkeypatch):
    state = SimpleNamespace(
        endpoints={"http://127.0.0.1/cart": {"method": "POST", "params": [{"name": "price"}]}},
        findings=[],
        target="http://127.0.0.1/",
    )
    config = AgentConfig(program="lab", target="http://127.0.0.1/")
    monkeypatch.setattr(
        "shroodler.llm_agent.payloads.complete_json",
        lambda *a, **k: llm_call.LlmJson(
            data={
                "hypotheses": [
                    {
                        "hypothesis": "tamper price to negative",
                        "target_url": "http://127.0.0.1/cart",
                        "reasoning": "price is client-supplied",
                        "severity": "high",
                    }
                ]
            }
        ),
    )
    result = payloads.analyze_logic(_decision("analyze_logic"), state, config)
    assert result.raw_output["queued"] == 1
    assert state.hypotheses[0]["hypothesis"] == "tamper price to negative"
    assert state.hypotheses[0]["source"] == "analyze_logic"


# --- craft_payloads classification ------------------------------------------


def test_classify_payload_result_signals():
    sql = payloads._classify_payload_result(
        "sqli", "' OR 1=1--", {"body": "You have an error in your SQL syntax"}
    )
    assert sql == "sql-error-reflected"
    ssti = payloads._classify_payload_result("ssti", "{{7*7}}", {"body": "result is 49"})
    assert ssti == "template-evaluated"
    xss = payloads._classify_payload_result("xss", "<svg>", {"body": "<script><svg></script>"})
    assert xss == "reflected-in-script"
    nothing = payloads._classify_payload_result("sqli", "x", {"body": "clean"})
    assert nothing == "no-signal"


# --- network tools with a mocked transport ----------------------------------


class _FakeResp:
    def __init__(self, status=200, body="", elapsed=0.05, ctype="text/html"):
        self.status_code = status
        self._body = body
        self.text = body
        self.content = body.encode()
        self.elapsed = elapsed
        self.headers = {"content-type": ctype}


def test_send_request_reports_reflection(monkeypatch):
    monkeypatch.setattr(
        "shroodler.llm_agent.http_tools.request",
        lambda method, url, **k: _FakeResp(body='<script>var v="INJ12345";</script>'),
    )
    config = AgentConfig(program="lab", target="http://127.0.0.1/")
    result = http_tools.send_request(
        _decision("send_request", url="http://127.0.0.1/s", params={"q": "INJ12345"}),
        config,
        Pacer(0.0),
        None,
    )
    assert result.raw_output["status_code"] == 200
    assert result.raw_output["reflected"] == {"INJ12345": "script"}
    assert "reflected" in result.summary


def test_send_request_transport_error(monkeypatch):
    monkeypatch.setattr("shroodler.llm_agent.http_tools.request", lambda *a, **k: None)
    config = AgentConfig(program="lab", target="http://127.0.0.1/")
    result = http_tools.send_request(
        _decision("send_request", url="http://127.0.0.1/s"), config, Pacer(0.0), None
    )
    assert result.raw_output["error"] == "transport"


def test_replay_as_user_flags_access_control(monkeypatch):
    # Owner and anon get the same 200 body → broken access control lead.
    monkeypatch.setattr(
        "shroodler.llm_agent.http_tools.request",
        lambda method, url, **k: _FakeResp(status=200, body="secret data"),
    )
    monkeypatch.setattr(
        "shroodler.llm_agent.http_tools._auth",
        lambda config: ("Cookie: owner=1", "Cookie: peer=1"),
    )
    config = AgentConfig(program="lab", target="http://127.0.0.1/")
    result = http_tools.replay_as_user(
        _decision("replay_as_user", url="http://127.0.0.1/acct"),
        config,
        Pacer(0.0),
        None,
    )
    assert set(result.raw_output["access_control_lead"]) == {"peer", "anon"}
    assert "broken access control" in result.summary


def test_compare_responses_detects_difference(monkeypatch):
    bodies = iter(["price=100", "price=1"])
    monkeypatch.setattr(
        "shroodler.llm_agent.http_tools.request",
        lambda method, url, **k: _FakeResp(body=next(bodies)),
    )
    monkeypatch.setattr(
        "shroodler.llm_agent.http_tools._auth",
        lambda config: ("Cookie: owner=1", ""),
    )
    config = AgentConfig(program="lab", target="http://127.0.0.1/")
    result = http_tools.compare_responses(
        _decision(
            "compare_responses",
            a={"url": "http://127.0.0.1/buy", "params": {"price": "100"}},
            b={"url": "http://127.0.0.1/buy", "params": {"price": "1"}},
        ),
        config,
        Pacer(0.0),
        None,
    )
    assert result.raw_output["identical"] is False


# --- default cost profile is DeepSeek ---------------------------------------


def test_default_config_uses_deepseek():
    cfg = AgentConfig(program="lab", target="http://127.0.0.1/")
    assert cfg.llm_provider == "deepseek"
    assert cfg.llm_agent_model == "deepseek-chat"
    assert cfg.llm_agent_reasoning_model == "deepseek-reasoner"


def test_reasoning_model_resolution():
    cfg = SimpleNamespace(
        llm_provider="deepseek",
        llm_agent_model="deepseek-chat",
        llm_agent_reasoning_model="deepseek-reasoner",
    )
    assert llm_call.planner_model_for(cfg) == "deepseek-chat"
    assert llm_call.reasoning_model_for(cfg) == "deepseek-reasoner"
    # Blank reasoning model falls back to the provider default reasoner.
    cfg.llm_agent_reasoning_model = ""
    assert llm_call.reasoning_model_for(cfg) == "deepseek-reasoner"
