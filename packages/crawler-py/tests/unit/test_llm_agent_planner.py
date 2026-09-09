from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from shroodler.agent import AgentConfig
from shroodler.llm_agent.planner import (
    DEFAULT_MODEL,
    OPUS_MODEL,
    PLANNER_MAX_TOKENS,
    PLANNER_TEMPERATURE,
    SYSTEM_PROMPT,
    estimate_cost_usd,
    plan_next_action,
    resolve_llm_agent_model,
)
from shroodler.llm_agent.tools import TOOLS


def _config(**kwargs) -> AgentConfig:
    defaults = {
        "program": "lab",
        "target": "http://127.0.0.1/",
        "llm_agent": True,
        "llm_agent_model": "claude-sonnet-5",
    }
    defaults.update(kwargs)
    return AgentConfig(**defaults)


def _fake_anthropic(text: str, input_tokens: int = 10, output_tokens: int = 5):
    block = MagicMock()
    block.text = text
    message = MagicMock()
    message.content = [block]
    message.usage = SimpleNamespace(input_tokens=input_tokens, output_tokens=output_tokens)
    client = MagicMock()
    client.messages.create.return_value = message
    return client


def test_resolve_model_aliases():
    assert resolve_llm_agent_model("") == DEFAULT_MODEL
    assert resolve_llm_agent_model("sonnet") == DEFAULT_MODEL
    assert resolve_llm_agent_model("opus") == OPUS_MODEL
    assert resolve_llm_agent_model("claude-opus-5") == OPUS_MODEL
    assert resolve_llm_agent_model("claude-sonnet-5") == DEFAULT_MODEL


def test_estimate_cost_uses_documented_rates():
    # sonnet $3/$15 per MTok
    assert estimate_cost_usd("claude-sonnet-5", 1_000_000, 1_000_000) == 18.0
    # opus $15/$75 per MTok
    assert estimate_cost_usd("claude-opus-5", 1_000_000, 0) == 15.0


def test_plan_parses_json_and_strips_fences(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    payload = (
        "```json\n"
        '{"action": "crawl", "params": {"url": "http://127.0.0.1/"}, '
        '"reasoning": "need surface"}\n'
        "```"
    )
    client = _fake_anthropic(payload)

    def _anth(*_a, **_k):
        return client

    monkeypatch.setattr("anthropic.Anthropic", _anth)
    decision = plan_next_action("TARGET: x", TOOLS, _config(), [])
    assert decision.fallback is False
    assert decision.action == "crawl"
    assert decision.params["url"] == "http://127.0.0.1/"
    assert decision.reasoning == "need surface"
    assert decision.input_tokens == 10
    kwargs = client.messages.create.call_args.kwargs
    assert kwargs["model"] == DEFAULT_MODEL
    assert kwargs["max_tokens"] == PLANNER_MAX_TOKENS
    assert kwargs["temperature"] == PLANNER_TEMPERATURE
    assert kwargs["system"] == SYSTEM_PROMPT


def test_plan_opus_model(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    client = _fake_anthropic(
        '{"action": "report", "params": {}, "reasoning": "done"}'
    )
    monkeypatch.setattr("anthropic.Anthropic", lambda *a, **k: client)
    decision = plan_next_action("c", TOOLS, _config(llm_agent_model="opus"), [])
    assert decision.action == "report"
    assert client.messages.create.call_args.kwargs["model"] == OPUS_MODEL


def test_plan_invalid_json_falls_back(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setattr("anthropic.Anthropic", lambda *a, **k: _fake_anthropic("not json"))
    decision = plan_next_action("c", TOOLS, _config(), [])
    assert decision.fallback is True
    assert decision.action is None
    assert "invalid JSON" in decision.fallback_reason


def test_plan_unknown_tool_falls_back(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setattr(
        "anthropic.Anthropic",
        lambda *a, **k: _fake_anthropic(
            '{"action": "drop_db", "params": {}, "reasoning": "nope"}'
        ),
    )
    decision = plan_next_action("c", TOOLS, _config(), [])
    assert decision.fallback is True
    assert decision.action is None
    assert "unknown tool" in decision.fallback_reason


def test_plan_missing_key_falls_back(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    def boom(*_a, **_k):
        raise AssertionError("must not call Anthropic without a key")

    monkeypatch.setattr("anthropic.Anthropic", boom, raising=False)
    decision = plan_next_action("c", TOOLS, _config(), [])
    assert decision.fallback is True
    assert "ANTHROPIC_API_KEY" in decision.fallback_reason
