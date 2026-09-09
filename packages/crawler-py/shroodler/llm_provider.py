"""LLM provider abstraction (Anthropic SDK + DeepSeek OpenAI-compatible HTTP).

Callers pass OpenAI-style chat messages and (optional) OpenAI tool schemas.
The Anthropic branch converts those at the provider boundary.
"""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

import httpx

# Documented list prices (USD per million tokens).
# Anthropic Sonnet 4 / 4.5 / 5 class: $3 input / $15 output.
# Anthropic Opus 4 / 4.5 / 5 class: $15 input / $75 output.
# DeepSeek: chat $0.27 / $1.10; reasoner $0.55 / $2.19.
# Source: provider pricing pages (2025–2026).
SONNET_INPUT_USD_PER_MTOK = 3.0
SONNET_OUTPUT_USD_PER_MTOK = 15.0
OPUS_INPUT_USD_PER_MTOK = 15.0
OPUS_OUTPUT_USD_PER_MTOK = 75.0
DEEPSEEK_CHAT_INPUT_USD_PER_MTOK = 0.27
DEEPSEEK_CHAT_OUTPUT_USD_PER_MTOK = 1.10
DEEPSEEK_REASONER_INPUT_USD_PER_MTOK = 0.55
DEEPSEEK_REASONER_OUTPUT_USD_PER_MTOK = 2.19

# USD per million tokens: (input, output). Name matches the public API.
COST_PER_TOKEN: dict[str, tuple[float, float]] = {
    "claude-sonnet-5": (SONNET_INPUT_USD_PER_MTOK, SONNET_OUTPUT_USD_PER_MTOK),
    "claude-opus-5": (OPUS_INPUT_USD_PER_MTOK, OPUS_OUTPUT_USD_PER_MTOK),
    "deepseek-chat": (DEEPSEEK_CHAT_INPUT_USD_PER_MTOK, DEEPSEEK_CHAT_OUTPUT_USD_PER_MTOK),
    "deepseek-reasoner": (
        DEEPSEEK_REASONER_INPUT_USD_PER_MTOK,
        DEEPSEEK_REASONER_OUTPUT_USD_PER_MTOK,
    ),
}

DEFAULT_MODELS: dict[str, str] = {
    "anthropic": "claude-sonnet-5",
    "deepseek": "deepseek-chat",
}

API_KEY_ENV: dict[str, str] = {
    "anthropic": "ANTHROPIC_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
}

DEFAULT_DEEPSEEK_BASE_URL = "https://api.deepseek.com"
DEFAULT_TIMEOUT_S = 60.0


class LLMProvider(StrEnum):
    ANTHROPIC = "anthropic"
    DEEPSEEK = "deepseek"


class LLMProviderError(Exception):
    """Raised when a provider call cannot be completed."""


@dataclass
class LLMConfig:
    provider: LLMProvider | str = LLMProvider.ANTHROPIC
    model: str = ""
    api_key: str | None = None
    base_url: str | None = None
    max_tokens: int = 512
    temperature: float = 0.0
    timeout: float = DEFAULT_TIMEOUT_S


@dataclass
class LLMResponse:
    text: str = ""
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    model: str = ""
    stop_reason: str = ""


def coerce_provider(value: Any) -> LLMProvider:
    raw = str(value or LLMProvider.ANTHROPIC.value).strip().lower()
    try:
        return LLMProvider(raw)
    except ValueError as exc:
        raise LLMProviderError(f"unknown LLM provider {value!r}") from exc


def llm_api_key_env(provider: LLMProvider | str | None) -> str:
    """Return the env var name that holds the API key for `provider`."""
    try:
        key = coerce_provider(provider).value
    except LLMProviderError:
        key = LLMProvider.ANTHROPIC.value
    return API_KEY_ENV.get(key, API_KEY_ENV[LLMProvider.ANTHROPIC.value])


def prices_for_model(model: str) -> tuple[float, float]:
    """Return (input_usd_per_mtok, output_usd_per_mtok) for `model`."""
    lowered = str(model or "").lower()
    if lowered in COST_PER_TOKEN:
        return COST_PER_TOKEN[lowered]
    for key, rates in COST_PER_TOKEN.items():
        if key in lowered:
            return rates
    if "opus" in lowered:
        return COST_PER_TOKEN["claude-opus-5"]
    return COST_PER_TOKEN["claude-sonnet-5"]


def estimate_cost_usd(model: str, input_tokens: int, output_tokens: int) -> float:
    inp, out = prices_for_model(model)
    return (max(0, int(input_tokens)) / 1_000_000.0) * inp + (
        max(0, int(output_tokens)) / 1_000_000.0
    ) * out


def tools_to_openai(tools: list[dict[str, Any]] | None) -> list[dict[str, Any]] | None:
    """Convert planner/Anthropic tool dicts to OpenAI function-tool schema."""
    if not tools:
        return None
    out: list[dict[str, Any]] = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        fn = tool.get("function")
        if tool.get("type") == "function" and isinstance(fn, dict):
            out.append(tool)
            continue
        name = str(tool.get("name") or "")
        if not name:
            continue
        description = str(tool.get("description") or "")
        params = (
            tool.get("parameters")
            if isinstance(tool.get("parameters"), dict)
            else None
        )
        if params is None and isinstance(tool.get("input_schema"), dict):
            params = tool.get("input_schema")
        if params is None:
            params = tool.get("params") if isinstance(tool.get("params"), dict) else {}
        if isinstance(params, dict) and params.get("type") == "object":
            schema = params
        else:
            properties: dict[str, Any] = {}
            for key, spec in (params or {}).items():
                if isinstance(spec, dict) and ("type" in spec or "description" in spec):
                    properties[str(key)] = spec
                else:
                    properties[str(key)] = {"type": "string", "description": str(spec)}
            schema = {"type": "object", "properties": properties}
        out.append(
            {
                "type": "function",
                "function": {
                    "name": name,
                    "description": description,
                    "parameters": schema,
                },
            }
        )
    return out or None


def _openai_tools_to_anthropic(
    tools: list[dict[str, Any]] | None,
) -> list[dict[str, Any]] | None:
    if not tools:
        return None
    out: list[dict[str, Any]] = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        fn = tool.get("function") if isinstance(tool.get("function"), dict) else None
        if fn is not None:
            schema = fn.get("parameters") or {"type": "object", "properties": {}}
            out.append(
                {
                    "name": fn.get("name") or "",
                    "description": fn.get("description") or "",
                    "input_schema": schema,
                }
            )
            continue
        if tool.get("name"):
            schema = tool.get("input_schema") or tool.get("parameters") or {
                "type": "object",
                "properties": {},
            }
            out.append(
                {
                    "name": tool.get("name"),
                    "description": tool.get("description") or "",
                    "input_schema": schema,
                }
            )
    return out or None


def _resolve_api_key(config: LLMConfig, provider: LLMProvider) -> str:
    env_name = llm_api_key_env(provider)
    key = config.api_key or os.environ.get(env_name)
    if not key:
        raise LLMProviderError(f"{env_name} is not set")
    return str(key)


def _resolve_model(config: LLMConfig, provider: LLMProvider) -> str:
    raw = str(config.model or "").strip()
    if raw:
        return raw
    return DEFAULT_MODELS[provider.value]


def _split_system(messages: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    system_parts: list[str] = []
    out: list[dict[str, Any]] = []
    for msg in messages or []:
        if not isinstance(msg, dict):
            continue
        role = str(msg.get("role") or "")
        content = msg.get("content")
        if role == "system":
            if isinstance(content, str):
                if content:
                    system_parts.append(content)
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict):
                        text = part.get("text")
                        if text:
                            system_parts.append(str(text))
                    elif part:
                        system_parts.append(str(part))
            elif content:
                system_parts.append(str(content))
            continue
        out.append({"role": role, "content": content})
    return "\n\n".join(system_parts), out


def _usage_tokens(message: Any) -> tuple[int, int]:
    usage = getattr(message, "usage", None)
    if usage is None:
        return 0, 0
    try:
        inp = int(getattr(usage, "input_tokens", 0) or 0)
    except (TypeError, ValueError):
        inp = 0
    try:
        out = int(getattr(usage, "output_tokens", 0) or 0)
    except (TypeError, ValueError):
        out = 0
    return max(0, inp), max(0, out)


def _parse_json_args(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if raw in (None, ""):
        return {}
    if isinstance(raw, str):
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, TypeError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}
    return {}


def _anthropic_content(message: Any) -> tuple[str, list[dict[str, Any]]]:
    content = getattr(message, "content", None) or []
    bits: list[str] = []
    tool_calls: list[dict[str, Any]] = []
    for block in content:
        block_type = getattr(block, "type", None)
        if block_type == "tool_use":
            args = getattr(block, "input", None)
            if not isinstance(args, dict):
                args = _parse_json_args(args)
            tool_calls.append(
                {
                    "id": str(getattr(block, "id", "") or ""),
                    "name": str(getattr(block, "name", "") or ""),
                    "arguments": args,
                }
            )
            continue
        text = getattr(block, "text", None)
        if text:
            bits.append(str(text))
    return "\n".join(bits), tool_calls


def _anthropic_client(config: LLMConfig, client: Any | None) -> Any:
    if client is not None:
        return client
    import anthropic

    # Existing tests patch anthropic.Anthropic and some fakes reject kwargs.
    if config.api_key:
        try:
            return anthropic.Anthropic(api_key=config.api_key)
        except TypeError:
            return anthropic.Anthropic()
    return anthropic.Anthropic()


async def _complete_anthropic(
    messages: list[dict[str, Any]],
    config: LLMConfig,
    tools: list[dict[str, Any]] | None,
    *,
    client: Any | None,
    model: str,
) -> LLMResponse:
    system, anth_messages = _split_system(messages)
    anthropic_client = _anthropic_client(config, client)
    kwargs: dict[str, Any] = {
        "model": model,
        "max_tokens": int(config.max_tokens),
        "temperature": config.temperature,
        "messages": anth_messages,
    }
    if system:
        kwargs["system"] = system
    anth_tools = _openai_tools_to_anthropic(tools)
    if anth_tools:
        kwargs["tools"] = anth_tools
        kwargs["tool_choice"] = {"type": "auto"}
    message = anthropic_client.messages.create(**kwargs)
    text, tool_calls = _anthropic_content(message)
    inp, out = _usage_tokens(message)
    stop = getattr(message, "stop_reason", None) or ""
    return LLMResponse(
        text=text,
        tool_calls=tool_calls,
        input_tokens=inp,
        output_tokens=out,
        model=model,
        stop_reason=str(stop),
    )


def _deepseek_tool_calls(message: dict[str, Any]) -> list[dict[str, Any]]:
    raw = message.get("tool_calls") or []
    out: list[dict[str, Any]] = []
    if not isinstance(raw, list):
        return out
    for item in raw:
        if not isinstance(item, dict):
            continue
        fn = item.get("function") if isinstance(item.get("function"), dict) else {}
        out.append(
            {
                "id": str(item.get("id") or ""),
                "name": str((fn or {}).get("name") or item.get("name") or ""),
                "arguments": _parse_json_args((fn or {}).get("arguments", item.get("arguments"))),
            }
        )
    return out


async def _complete_deepseek(
    messages: list[dict[str, Any]],
    config: LLMConfig,
    tools: list[dict[str, Any]] | None,
    *,
    api_key: str,
    model: str,
) -> LLMResponse:
    base = str(config.base_url or DEFAULT_DEEPSEEK_BASE_URL).rstrip("/")
    url = f"{base}/v1/chat/completions"
    body: dict[str, Any] = {
        "model": model,
        "messages": list(messages or []),
        "max_tokens": int(config.max_tokens),
        "temperature": config.temperature,
    }
    if tools:
        body["tools"] = tools
        body["tool_choice"] = "auto"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    timeout = float(config.timeout or DEFAULT_TIMEOUT_S)
    try:
        async with httpx.AsyncClient(timeout=timeout) as http:
            resp = await http.post(url, headers=headers, json=body)
    except httpx.HTTPError as exc:
        raise LLMProviderError(f"DeepSeek request failed: {exc}") from exc
    if resp.status_code < 200 or resp.status_code >= 300:
        body_text = getattr(resp, "text", None) or ""
        raise LLMProviderError(f"DeepSeek HTTP {resp.status_code}: {body_text}")
    try:
        payload = resp.json()
    except Exception as exc:  # noqa: BLE001
        raise LLMProviderError(f"DeepSeek returned non-JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise LLMProviderError("DeepSeek returned a non-object JSON body")
    choices = payload.get("choices") or []
    choice = choices[0] if choices and isinstance(choices[0], dict) else {}
    message = choice.get("message") if isinstance(choice.get("message"), dict) else {}
    content = message.get("content")
    text = content if isinstance(content, str) else ("" if content is None else str(content))
    usage = payload.get("usage") if isinstance(payload.get("usage"), dict) else {}
    try:
        inp = int(usage.get("prompt_tokens") or usage.get("input_tokens") or 0)
    except (TypeError, ValueError):
        inp = 0
    try:
        out = int(usage.get("completion_tokens") or usage.get("output_tokens") or 0)
    except (TypeError, ValueError):
        out = 0
    stop = choice.get("finish_reason") or payload.get("stop_reason") or ""
    return LLMResponse(
        text=text,
        tool_calls=_deepseek_tool_calls(message),
        input_tokens=max(0, inp),
        output_tokens=max(0, out),
        model=str(payload.get("model") or model),
        stop_reason=str(stop),
    )


async def llm_complete(
    messages: list[dict[str, Any]],
    config: LLMConfig,
    tools: list[dict[str, Any]] | None = None,
    *,
    client: Any = None,
) -> LLMResponse:
    """Complete a chat turn. `tools` must be OpenAI function-tool schema or None."""
    provider = coerce_provider(config.provider)
    api_key = _resolve_api_key(config, provider)
    model = _resolve_model(config, provider)
    openai_tools = tools if tools else None
    if provider is LLMProvider.ANTHROPIC:
        return await _complete_anthropic(
            messages, config, openai_tools, client=client, model=model
        )
    if provider is LLMProvider.DEEPSEEK:
        return await _complete_deepseek(
            messages, config, openai_tools, api_key=api_key, model=model
        )
    raise LLMProviderError(f"unknown LLM provider {provider!r}")


def llm_complete_sync(
    messages: list[dict[str, Any]],
    config: LLMConfig,
    tools: list[dict[str, Any]] | None = None,
    *,
    client: Any = None,
) -> LLMResponse:
    """Sync wrapper for the existing sync planner / triage / business-logic APIs."""
    return asyncio.run(llm_complete(messages, config, tools, client=client))
