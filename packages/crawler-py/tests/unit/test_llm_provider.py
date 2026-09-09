from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from shroodler.llm_provider import (
    COST_PER_TOKEN,
    LLMConfig,
    LLMProvider,
    LLMProviderError,
    estimate_cost_usd,
    llm_api_key_env,
    llm_complete,
    llm_complete_sync,
    tools_to_openai,
)


def _run(coro):
    return asyncio.run(coro)


def _anthropic_text_message(text: str, *, input_tokens: int = 3, output_tokens: int = 2):
    block = MagicMock()
    block.type = "text"
    block.text = text
    message = MagicMock()
    message.content = [block]
    message.usage = SimpleNamespace(input_tokens=input_tokens, output_tokens=output_tokens)
    message.stop_reason = "end_turn"
    return message


def _patch_anthropic(monkeypatch, create):
    class Fake:
        def __init__(self, *args, **kwargs):
            self.messages = self

        def create(self, **kwargs):
            return create(kwargs)

    monkeypatch.setattr("anthropic.Anthropic", Fake)


def _patch_httpx(monkeypatch, *, status=200, payload=None, text=None):
    recorded: dict = {}
    payload = {} if payload is None else payload

    class Resp:
        status_code = status

        def json(self):
            return payload

        @property
        def text(self):
            return text if text is not None else json.dumps(payload)

    class Client:
        def __init__(self, *args, **kwargs):
            recorded["client_kwargs"] = kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, url, **kwargs):
            recorded["url"] = url
            recorded["headers"] = kwargs.get("headers")
            recorded["json"] = kwargs.get("json")
            return Resp()

    monkeypatch.setattr("shroodler.llm_provider.httpx.AsyncClient", Client)
    return recorded


def test_provider_enum():
    assert LLMProvider("deepseek") == LLMProvider.DEEPSEEK
    assert LLMProvider("anthropic") == LLMProvider.ANTHROPIC
    assert llm_api_key_env(LLMProvider.DEEPSEEK) == "DEEPSEEK_API_KEY"
    assert llm_api_key_env("anthropic") == "ANTHROPIC_API_KEY"


def test_missing_anthropic_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(LLMProviderError) as exc:
        _run(
            llm_complete(
                [{"role": "user", "content": "hi"}],
                LLMConfig(provider=LLMProvider.ANTHROPIC, api_key=""),
            )
        )
    assert "ANTHROPIC_API_KEY" in str(exc.value)


def test_missing_deepseek_key(monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    with pytest.raises(LLMProviderError) as exc:
        _run(
            llm_complete(
                [{"role": "user", "content": "hi"}],
                LLMConfig(provider=LLMProvider.DEEPSEEK, api_key=""),
            )
        )
    assert "DEEPSEEK_API_KEY" in str(exc.value)


def test_anthropic_extracts_system_and_omits_tools(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    captured = {}

    def create(kwargs):
        captured.update(kwargs)
        return _anthropic_text_message("hello")

    _patch_anthropic(monkeypatch, create)
    resp = _run(
        llm_complete(
            [
                {"role": "system", "content": "sys"},
                {"role": "user", "content": "hi"},
            ],
            LLMConfig(provider=LLMProvider.ANTHROPIC, model=""),
        )
    )
    assert captured["system"] == "sys"
    assert captured["messages"] == [{"role": "user", "content": "hi"}]
    assert captured["model"] == "claude-sonnet-5"
    assert "tools" not in captured
    assert "tool_choice" not in captured
    assert resp.text == "hello"
    assert resp.input_tokens == 3
    assert resp.output_tokens == 2
    assert resp.stop_reason == "end_turn"
    assert resp.model == "claude-sonnet-5"


def test_anthropic_converts_openai_tools(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    captured = {}

    def create(kwargs):
        captured.update(kwargs)
        return _anthropic_text_message("ok")

    _patch_anthropic(monkeypatch, create)
    tools = [
        {
            "type": "function",
            "function": {
                "name": "crawl",
                "description": "crawl urls",
                "parameters": {
                    "type": "object",
                    "properties": {"url": {"type": "string"}},
                },
            },
        }
    ]
    _run(
        llm_complete(
            [{"role": "user", "content": "go"}],
            LLMConfig(provider="anthropic", model="claude-sonnet-5"),
            tools=tools,
        )
    )
    assert captured["tools"][0]["name"] == "crawl"
    assert captured["tools"][0]["input_schema"]["type"] == "object"
    assert captured["tool_choice"] == {"type": "auto"}


def test_anthropic_maps_tool_use_blocks(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")

    def create(_kwargs):
        block = MagicMock()
        block.type = "tool_use"
        block.name = "crawl"
        block.id = "toolu_1"
        block.input = {"url": "http://x"}
        block.text = None
        message = MagicMock()
        message.content = [block]
        message.usage = SimpleNamespace(input_tokens=1, output_tokens=1)
        message.stop_reason = "tool_use"
        return message

    _patch_anthropic(monkeypatch, create)
    resp = llm_complete_sync(
        [{"role": "user", "content": "go"}],
        LLMConfig(provider=LLMProvider.ANTHROPIC, api_key="sk-test"),
    )
    assert resp.text == ""
    assert resp.tool_calls[0]["name"] == "crawl"
    assert resp.tool_calls[0]["arguments"] == {"url": "http://x"}
    assert resp.stop_reason == "tool_use"


def test_deepseek_default_model_and_omits_tools(monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    payload = {
        "model": "deepseek-chat",
        "choices": [
            {
                "message": {"content": "pong"},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 4, "completion_tokens": 6},
    }
    recorded = _patch_httpx(monkeypatch, payload=payload)
    resp = _run(
        llm_complete(
            [{"role": "user", "content": "ping"}],
            LLMConfig(provider=LLMProvider.DEEPSEEK, model="", api_key="sk-ds"),
        )
    )
    assert recorded["url"] == "https://api.deepseek.com/v1/chat/completions"
    body = recorded["json"]
    assert body["model"] == "deepseek-chat"
    assert "tools" not in body
    assert "tool_choice" not in body
    assert recorded["headers"]["Authorization"] == "Bearer sk-ds"
    assert resp.text == "pong"
    assert resp.input_tokens == 4
    assert resp.output_tokens == 6
    assert resp.stop_reason == "stop"


def test_deepseek_parses_tool_call_arguments(monkeypatch):
    payload = {
        "choices": [
            {
                "message": {
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {
                                "name": "crawl",
                                "arguments": '{"url": "http://x"}',
                            },
                        },
                        {
                            "id": "call_2",
                            "type": "function",
                            "function": {
                                "name": "report",
                                "arguments": {},
                            },
                        },
                    ],
                },
                "finish_reason": "tool_calls",
            }
        ],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
    }
    _patch_httpx(monkeypatch, payload=payload)
    resp = _run(
        llm_complete(
            [{"role": "user", "content": "go"}],
            LLMConfig(
                provider=LLMProvider.DEEPSEEK,
                model="deepseek-chat",
                api_key="sk-ds",
            ),
            tools=tools_to_openai(
                [{"name": "crawl", "description": "c", "params": {"url": "str"}}]
            ),
        )
    )
    assert resp.tool_calls[0]["name"] == "crawl"
    assert resp.tool_calls[0]["arguments"] == {"url": "http://x"}
    assert resp.tool_calls[1]["arguments"] == {}
    assert resp.stop_reason == "tool_calls"


def test_deepseek_includes_tools_when_provided(monkeypatch):
    recorded = _patch_httpx(
        monkeypatch,
        payload={"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]},
    )
    tools = [
        {
            "type": "function",
            "function": {"name": "report", "description": "done", "parameters": {}},
        }
    ]
    _run(
        llm_complete(
            [{"role": "user", "content": "go"}],
            LLMConfig(provider="deepseek", api_key="sk-ds"),
            tools=tools,
        )
    )
    assert recorded["json"]["tools"] == tools
    assert recorded["json"]["tool_choice"] == "auto"


def test_deepseek_non_2xx_includes_body(monkeypatch):
    _patch_httpx(monkeypatch, status=401, payload={"error": "nope"}, text='{"error":"nope"}')
    with pytest.raises(LLMProviderError) as exc:
        _run(
            llm_complete(
                [{"role": "user", "content": "hi"}],
                LLMConfig(provider=LLMProvider.DEEPSEEK, api_key="sk-ds"),
            )
        )
    assert "401" in str(exc.value)
    assert "nope" in str(exc.value)


def test_estimate_cost_usd_rates():
    assert estimate_cost_usd("deepseek-chat", 1_000_000, 1_000_000) == 1.37
    assert estimate_cost_usd("deepseek-reasoner", 1_000_000, 1_000_000) == 2.74
    assert estimate_cost_usd("claude-sonnet-5", 1_000_000, 1_000_000) == 18.0
    assert estimate_cost_usd("claude-opus-5", 1_000_000, 0) == 15.0
    assert COST_PER_TOKEN["deepseek-chat"] == (0.27, 1.10)


def test_tools_to_openai_keeps_planner_schema_convertible():
    converted = tools_to_openai(
        [{"name": "crawl", "description": "c", "params": {"url": "str | None"}}]
    )
    assert converted is not None
    assert converted[0]["type"] == "function"
    assert converted[0]["function"]["name"] == "crawl"
    assert converted[0]["function"]["parameters"]["type"] == "object"
