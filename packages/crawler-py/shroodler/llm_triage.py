"""Opt-in Claude ranking of unconfirmed IDOR leads.

Never raises: every failure path returns the caller's original order.
The prompt includes finding IDs and severities only — never descriptions.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from shroodler.llm_provider import (
    LLMConfig,
    LLMProvider,
    llm_api_key_env,
    llm_complete_sync,
)
from shroodler.program import (
    _INT_ID_RE,
    _UUID_RE,
    ProgramState,
    url_to_pattern,
)

TRIAGE_MODEL = "claude-haiku-4-5-20251001"

SYSTEM_PROMPT = (
    "You are a bug bounty triage assistant. Given a list of object IDs and "
    "endpoints from a web app crawl, rank them by likelihood of containing an "
    "IDOR or broken access control vulnerability. Prefer integer/sequential IDs "
    "over UUIDs. Prefer write endpoints over read-only. Prefer endpoints in API "
    "paths over static/asset paths. Return a JSON object: "
    '{"ranked_ids": [...], "ranked_urls": [...], "rationale": "one sentence"}.'
)

_FALLBACK_RATIONALE = "fallback: LLM unavailable"


@dataclass
class TriageResult:
    ranked_ids: list[str]
    ranked_urls: list[str]
    rationale: str
    used_llm: bool


def classify_id_shape(value: str) -> str:
    """Detect UUID / integer / slug from the ID string itself."""
    text = str(value or "").strip()
    if _UUID_RE.fullmatch(text):
        return "uuid"
    if _INT_ID_RE.fullmatch(text):
        return "integer"
    return "slug"


def local_rank_ids(object_ids: list[str]) -> list[str]:
    """Prefer integer/sequential IDs over slugs over UUIDs. Stable within a shape."""
    order = {"integer": 0, "slug": 1, "uuid": 2}
    indexed = list(enumerate(object_ids))
    indexed.sort(key=lambda item: (order.get(classify_id_shape(item[1]), 1), item[0]))
    return [oid for _, oid in indexed]


rank_ids_heuristic = local_rank_ids


def _fallback(object_ids: list[str], authz_urls: list[str]) -> TriageResult:
    return TriageResult(
        ranked_ids=list(object_ids),
        ranked_urls=list(authz_urls),
        rationale=_FALLBACK_RATIONALE,
        used_llm=False,
    )


def _log_error(exc: BaseException) -> None:
    print(
        json.dumps({"error": f"llm_triage: {type(exc).__name__}: {exc}"}, default=str),
        file=sys.stderr,
        flush=True,
    )


def _owning_endpoints(state: ProgramState, object_id: str) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for pattern, ids in state.object_ids.items():
        if object_id not in ids:
            continue
        if pattern not in seen:
            seen.add(pattern)
            urls.append(pattern)
        for url in state.endpoints:
            if url_to_pattern(url) != pattern:
                continue
            if url not in seen:
                seen.add(url)
                urls.append(url)
    if not urls:
        for url in state.endpoints:
            if object_id in url and url not in seen:
                seen.add(url)
                urls.append(url)
    return urls


def _target_origin(target: str) -> str:
    parsed = urlparse(target or "")
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return target or ""


def _confirmed_briefing(state: ProgramState) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for finding in state.findings:
        if getattr(finding, "confidence", None) != "confirmed":
            continue
        out.append(
            {
                "id": str(getattr(finding, "id", "") or ""),
                "severity": str(getattr(finding, "severity", "") or ""),
            }
        )
        if len(out) >= 5:
            break
    return out


def _authz_briefing(state: ProgramState, authz_urls: list[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for url in authz_urls:
        meta = state.endpoints.get(url) or {}
        status = meta.get("status_code")
        if status is None:
            status = meta.get("higher_priv_status")
        method = meta.get("method") or meta.get("http_method") or ""
        higher_priv_200 = status == 200
        out.append(
            {
                "url": url,
                "pattern": url_to_pattern(url),
                "method": str(method) if method else "unknown",
                "higher_priv_200": higher_priv_200,
            }
        )
    return out


def _id_briefing(state: ProgramState, object_ids: list[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for oid in object_ids:
        owners = _owning_endpoints(state, oid)
        out.append(
            {
                "id": oid,
                "shape": classify_id_shape(oid),
                "endpoint": owners[0] if owners else "",
            }
        )
    return out


def _strip_fences(text: str) -> str:
    stripped = (text or "").strip()
    if not stripped.startswith("```"):
        return stripped
    lines = stripped.split("\n")
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip().startswith("```"):
        lines = lines[:-1]
    return "\n".join(lines).strip()


def _parse_json_object(text: str) -> dict[str, Any] | None:
    candidate = _strip_fences(text)
    try:
        data = json.loads(candidate)
        if isinstance(data, dict):
            return data
    except (json.JSONDecodeError, TypeError, ValueError):
        pass
    start = candidate.find("{")
    end = candidate.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        data = json.loads(candidate[start : end + 1])
    except (json.JSONDecodeError, TypeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _merge_rank(ranked: list[str], original: list[str]) -> list[str]:
    orig_set = set(original)
    out: list[str] = []
    seen: set[str] = set()
    for item in ranked:
        value = str(item)
        if value in orig_set and value not in seen:
            out.append(value)
            seen.add(value)
    for item in original:
        if item not in seen:
            out.append(item)
            seen.add(item)
    return out


def _build_user_prompt(
    state: ProgramState,
    object_ids: list[str],
    authz_urls: list[str],
    config: Any,
) -> str:
    target = str(getattr(config, "target", "") or "")
    payload = {
        "program": state.slug,
        "target_origin": _target_origin(target),
        "object_ids": _id_briefing(state, object_ids),
        "authz_urls": _authz_briefing(state, authz_urls),
        "confirmed_findings": _confirmed_briefing(state),
    }
    return json.dumps(payload, default=str)


def _provider_for(config: Any) -> LLMProvider:
    raw = str(getattr(config, "llm_provider", "anthropic") or "anthropic")
    try:
        return LLMProvider(raw.strip().lower())
    except ValueError:
        return LLMProvider.ANTHROPIC


def _model_for(config: Any, provider: LLMProvider) -> str:
    raw = str(getattr(config, "llm_agent_model", "") or "").strip()
    if provider is LLMProvider.DEEPSEEK:
        lowered = raw.lower()
        if not raw or lowered in {"sonnet", "opus", "claude-sonnet-5", "claude-opus-5"}:
            return ""
        return raw
    if not raw or raw.lower() in {"sonnet", "claude-sonnet-5"}:
        return TRIAGE_MODEL
    return raw


def triage_leads(
    state: ProgramState,
    object_ids: list[str],
    authz_urls: list[str],
    config: Any,
) -> TriageResult:
    """Rank unconfirmed leads. Never raises; falls back to the input order."""
    fallback = _fallback(object_ids, authz_urls)
    try:
        provider = _provider_for(config)
        if not os.environ.get(llm_api_key_env(provider)):
            return fallback
        user_prompt = _build_user_prompt(state, object_ids, authz_urls, config)
        llm_config = LLMConfig(
            provider=provider,
            model=_model_for(config, provider),
            max_tokens=512,
            temperature=0,
        )
        response = llm_complete_sync(
            [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            llm_config,
        )
        data = _parse_json_object(response.text)
        if data is None:
            return fallback
        ranked_ids = data.get("ranked_ids")
        ranked_urls = data.get("ranked_urls")
        if not isinstance(ranked_ids, list) or not isinstance(ranked_urls, list):
            return fallback
        rationale = " ".join(str(data.get("rationale") or "").split()) or "llm triage"
        return TriageResult(
            ranked_ids=_merge_rank([str(x) for x in ranked_ids], list(object_ids)),
            ranked_urls=_merge_rank([str(x) for x in ranked_urls], list(authz_urls)),
            rationale=rationale,
            used_llm=True,
        )
    except Exception as exc:  # noqa: BLE001 - triage must never raise
        _log_error(exc)
        return fallback
