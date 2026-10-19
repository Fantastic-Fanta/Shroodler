"""Autonomous engagement loop over per-program state.

Reads ~/.shroodler/programs/<slug>/state.json, picks the next highest-value
action (login → tls-check → crawl → js-analysis → diff → waf-detect →
openapi-discover → auto-register → authz-diff → idor-scan → write-authz →
peer-write → content-discover → probe → openapi-probe → business-logic →
chain → report),
executes it through existing Shroodler APIs, merges results, and repeats until
the iteration budget is exhausted or there is nothing left to do.

No new dependencies. Single-threaded. Dry-run makes no HTTP requests.
"""

from __future__ import annotations

import copy
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from shroodler import program
from shroodler.agent_types import (
    AgentAction,
    AgentConfig,
    AgentResult,
    AuthzDiffAction,
    AutoRegisterAction,
    BusinessLogicAction,
    ChainAction,
    ContentDiscoverAction,
    CrawlAction,
    DiffAction,
    IDORScanAction,
    JSAnalysisAction,
    LoginAction,
    OpenApiDiscoverAction,
    OpenApiProbeAction,
    PeerWriteAction,
    ProbeAction,
    ReportAction,
    TLSCheckAction,
    WafDetectAction,
    WriteAuthzAction,
)
from shroodler.models import Finding
from shroodler.pacer import Pacer
from shroodler.program import ProgramState, object_ids_flat, url_to_pattern
from shroodler.urls import is_loopback_or_local, same_origin
from shroodler.util import now_iso, now_utc

_STALE_AFTER = timedelta(hours=24)
_DEFAULT_RATE_CEILING = 0.1  # 100 ms between HTTP requests if no guardrail
_AGG_WORKERS = 8  # concurrent endpoint probes in --aggressive mode
_PROBE_WORKERS = 4  # non-aggressive: several URLs in flight, still paced
_AGG_TIMEOUT = 4.0  # per-request timeout (s) in --aggressive mode (default 8)
_CRAWL_STALL_LIMIT = 3
_PLACEHOLDER_RE = re.compile(r"\{[^{}]+\}")



def _parse_ts(raw: str | None) -> datetime | None:
    if not raw:
        return None
    text = str(raw).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def _in_target_origin(url: str, target: str) -> bool:
    if not url or not target:
        return False
    try:
        return same_origin(url, target)
    except ValueError:
        return False


def _scope_dict(state: ProgramState, config: AgentConfig) -> dict:
    from shroodler.scope import load_scope

    path = getattr(config, "scope_file", None)
    return load_scope(state.slug, path=path)


def _url_in_program_scope(url: str, state: ProgramState, config: AgentConfig) -> bool:
    from shroodler.scope import in_scope, path_denied

    scope = _scope_dict(state, config)
    if path_denied(url, scope):
        emit_log_entry({"debug": "scope-deny", "url": url})
        return False
    if in_scope(url, scope):
        return True
    emit_log_entry({"debug": "scope-excluded", "url": url})
    return False


def _allow_external(target: str) -> bool:
    return not is_loopback_or_local(target)


def assert_target_in_scope(state: ProgramState, target: str) -> None:
    """Refuse to start if the program has a scope and target is not in it."""
    if not state.scope_urls:
        return
    for scoped in state.scope_urls:
        if scoped and _in_target_origin(target, scoped):
            return
    raise ValueError(
        f"target {target!r} is not in program {state.slug!r} scope "
        f"(scope_urls={list(state.scope_urls)!r}); refusing to start the agent loop"
    )


def _rate_interval() -> float:
    """Prefer guardrails.rate_ceiling when present; else 100 ms."""
    try:
        from shroodler_guardrails import rate_ceiling as rc
    except ImportError:
        return _DEFAULT_RATE_CEILING
    if isinstance(rc, (int, float)):
        return max(0.0, float(rc))
    if callable(rc):
        try:
            value = rc()
        except TypeError:
            return _DEFAULT_RATE_CEILING
        if isinstance(value, (int, float)):
            return max(0.0, float(value))
    return _DEFAULT_RATE_CEILING


def _new_pacer() -> Pacer:
    return Pacer(_rate_interval())


def crawl_coverage_gaps(state: ProgramState, config: AgentConfig) -> list[str]:
    """Endpoints with last_seen older than 24h, or never crawled.

    Distinct from program.coverage_gaps (which is untested-authz/peer-write).
    An empty endpoint map means the target itself has never been crawled.
    Out-of-origin URLs are never queued.
    """
    cap = max(0, int(config.max_pages_per_crawl))
    now = now_utc()
    stale: list[tuple[str, str]] = []
    for url, meta in state.endpoints.items():
        if not _in_target_origin(url, config.target):
            continue
        if not _url_in_program_scope(url, state, config):
            continue
        if _has_unresolved_placeholder(url):
            continue
        last_seen = str((meta or {}).get("last_seen") or "")
        ts = _parse_ts(last_seen)
        if ts is None or (now - ts) > _STALE_AFTER:
            stale.append((url, last_seen))
    stale.sort(key=lambda item: item[1] or "")
    urls = [url for url, _ in stale]
    if not state.endpoints and _in_target_origin(config.target, config.target):
        if _url_in_program_scope(config.target, state, config):
            urls = [config.target]
    elif not urls and not any(
        _in_target_origin(u, config.target) for u in state.endpoints
    ):
        if _in_target_origin(config.target, config.target) and _url_in_program_scope(
            config.target, state, config
        ):
            urls = [config.target]
    return urls[:cap]


def _untested_authz_urls(state: ProgramState, config: AgentConfig) -> list[str]:
    cap = max(0, int(config.max_pages_per_crawl))
    ranked: list[tuple[int, int, str]] = []
    for index, (url, meta) in enumerate(state.endpoints.items()):
        if not _in_target_origin(url, config.target):
            continue
        if not _url_in_program_scope(url, state, config):
            continue
        meta = meta or {}
        if bool(meta.get("tested_authz")):
            continue
        ranked.append((_probe_rank(url, meta), index, url))
    ranked.sort()
    return [url for _, _, url in ranked[:cap]]


_PROBE_PRIORITY = (
    "sqlinjection",
    "pathtraversal",
    "crositescripting",
    "/jwt/",
    "/idor/",
    "access-control",
)


# js-analysis ghost routes sit ahead of generic crawled pages (50/100) but
# behind the named _PROBE_PRIORITY tokens (0-5).
_JS_ANALYSIS_PROBE_RANK = 40


def _probe_rank(url: str, meta: dict | None) -> int:
    path = (url or "").lower()
    rank = 100
    for i, token in enumerate(_PROBE_PRIORITY):
        if token in path:
            rank = i
            break
    else:
        if (meta or {}).get("params"):
            rank = 50
    if (meta or {}).get("source") == "js-analysis":
        rank = min(rank, _JS_ANALYSIS_PROBE_RANK)
    return rank


def _stale_payload(meta: dict | None) -> bool:
    """Re-queue when params exist and last_seen is newer than tested_payload_at."""
    meta = meta or {}
    params = meta.get("params") or []
    if not params:
        return False
    last_seen = _parse_ts(str(meta.get("last_seen") or "") or None)
    tested_at = _parse_ts(str(meta.get("tested_payload_at") or "") or None)
    if last_seen is None or tested_at is None:
        return False
    return last_seen > tested_at


def _untested_probe_urls(state: ProgramState, config: AgentConfig) -> list[str]:
    cap = max(0, int(config.max_pages_per_crawl))
    ranked: list[tuple[int, int, str]] = []
    for index, (url, meta) in enumerate(state.endpoints.items()):
        if not _in_target_origin(url, config.target):
            continue
        if not _url_in_program_scope(url, state, config):
            continue
        meta = meta or {}
        if (
            str(meta.get("source") or "") == "js-analysis"
            and not _has_owner_session(config)
            and not _looks_like_api_route(url)
        ):
            continue
        if _has_unresolved_placeholder(url):
            continue
        if bool(meta.get("tested_payload")) and not _stale_payload(meta):
            continue
        ranked.append((_probe_rank(url, meta), index, url))
    ranked.sort()
    return [url for _, _, url in ranked[:cap]]


def _untested_openapi_endpoints(state: ProgramState, config: AgentConfig) -> list[dict]:
    cap = max(0, int(config.max_pages_per_crawl))
    out: list[dict] = []
    for row in state.openapi_endpoints or []:
        if not isinstance(row, dict):
            continue
        url = str(row.get("url") or "")
        if not url:
            continue
        if not _in_target_origin(url, config.target):
            continue
        meta = state.endpoints.get(url) or {}
        if bool(meta.get("tested_payload")) or bool(row.get("tested_payload")):
            continue
        out.append(row)
        if len(out) >= cap:
            break
    return out


def _reset_tested_payload(state: ProgramState) -> int:
    n = 0
    for meta in state.endpoints.values():
        if not isinstance(meta, dict):
            continue
        if meta.get("tested_payload"):
            meta["tested_payload"] = False
            n += 1
    return n


def _backfill_authz_confidence(state: ProgramState) -> int:
    """Existing authz-broken-access-control leads already passed peer=200/anon=denied."""
    n = 0
    for finding in state.findings:
        if finding.id != "authz-broken-access-control":
            continue
        if finding.confidence is None:
            finding.confidence = "confirmed"
            n += 1
    return n


def _owning_endpoints(state: ProgramState, object_id: str) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for pattern, ids in state.object_ids.items():
        if object_id not in ids:
            continue
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


def _pending_peer_write_ids(state: ProgramState, config: AgentConfig) -> list[str]:
    cap = max(0, int(config.max_pages_per_crawl))
    pending: list[str] = []
    for oid in object_ids_flat(state):
        owners = _owning_endpoints(state, oid)
        if not owners:
            continue
        in_origin = [u for u in owners if _in_target_origin(u, config.target)]
        if not in_origin:
            continue
        if all(bool((state.endpoints.get(u) or {}).get("tested_peer_write")) for u in in_origin):
            continue
        pending.append(oid)
        if len(pending) >= cap:
            break
    return pending


_TOOL_NOISE_IDS = frozenset({"session-died", "robots-blocked-crawl"})


def _confirmed_findings(state: ProgramState) -> list[Finding]:
    from shroodler.engagement_history import is_suppressed

    return [
        f
        for f in state.findings
        if getattr(f, "confidence", None) == "confirmed"
        and getattr(f, "id", None) not in _TOOL_NOISE_IDS
        and not is_suppressed(
            state,
            str(getattr(f, "id", "") or ""),
            str(getattr(f, "url", "") or ""),
        )
    ]


def _ensure_write_authz_endpoints(config: AgentConfig) -> list[dict]:
    existing = config.write_authz_endpoints
    if existing:
        return list(existing)
    spec = config.write_authz_spec
    if not spec:
        return []
    path = Path(spec)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"write-authz spec {spec!r} could not be loaded: {exc}") from exc
    if not isinstance(data, list):
        raise ValueError(f"write-authz spec {spec!r} must be a JSON array of probes")
    loaded = [item for item in data if isinstance(item, dict)]
    config.write_authz_endpoints = loaded
    return loaded


def _should_run_diff(state: ProgramState, config: AgentConfig) -> bool:
    if getattr(config, "_diff_done", False):
        return False
    if config.run_diff:
        return True
    if state.run_history:
        return True
    prev = getattr(config, "_prev_endpoints", None)
    if getattr(config, "_crawled_this_run", False) and prev:
        return True
    return False


def _pending_business_logic(config: AgentConfig) -> bool:
    if getattr(config, "_business_logic_done", False):
        return False
    return bool(config.run_business_logic)


def _pending_chains(state: ProgramState, config: AgentConfig) -> bool:
    if getattr(config, "_chain_done", False):
        return False
    if config.chain_specs:
        return True
    if not config.run_probes:
        return False
    from shroodler.attack_chain import bind_builtin_chains

    return bool(bind_builtin_chains(state, config))


def _has_owner_session(config: AgentConfig) -> bool:
    return bool(
        (config.higher_priv_jar or "").strip() or (config.owner_cookie or "").strip()
    )


def _looks_like_api_route(url: str) -> bool:
    path = (urlparse(url).path or "").lower()
    return any(
        token in path
        for token in (
            "/api/",
            "/rest/",
            "/graphql",
            "/auth/",
            "/oauth",
            "/.well-known/",
        )
    )


def _has_peer_session(config: AgentConfig) -> bool:
    return bool(
        (config.lower_priv_jar or "").strip() or (config.peer_cookie or "").strip()
    )


def _has_idor_dual_sessions(state: ProgramState, config: AgentConfig) -> bool:
    owner_state = bool(
        dict(getattr(state, "login_headers", None) or {})
        or dict(getattr(state, "login_cookies", None) or {})
    )
    peer_state = bool(
        dict(getattr(state, "peer_headers", None) or {})
        or dict(getattr(state, "peer_cookies", None) or {})
    )
    if owner_state and peer_state:
        return True
    return bool(
        (config.owner_cookie or "").strip() and (config.peer_cookie or "").strip()
    )


def _pending_idor_scan(state: ProgramState, config: AgentConfig) -> bool:
    if getattr(config, "_idor_scan_done", False):
        return False
    if not _has_idor_dual_sessions(state, config):
        return False
    from shroodler.idor_engine import collect_idor_targets

    return bool(collect_idor_targets(state, config))


def _resolve_idor_sessions(
    state: ProgramState, config: AgentConfig
) -> tuple[dict[str, str], dict[str, str], dict[str, str], dict[str, str]] | None:
    from shroodler.idor_engine import session_from_auth_line

    owner_headers = dict(getattr(state, "login_headers", None) or {})
    owner_cookies = dict(getattr(state, "login_cookies", None) or {})
    peer_headers = dict(getattr(state, "peer_headers", None) or {})
    peer_cookies = dict(getattr(state, "peer_cookies", None) or {})
    oh, oc = session_from_auth_line(config.owner_cookie or "")
    ph, pc = session_from_auth_line(config.peer_cookie or "")
    for key, value in oh.items():
        owner_headers.setdefault(key, value)
    for key, value in oc.items():
        owner_cookies.setdefault(key, value)
    for key, value in ph.items():
        peer_headers.setdefault(key, value)
    for key, value in pc.items():
        peer_cookies.setdefault(key, value)
    if not (owner_headers or owner_cookies):
        return None
    if not (peer_headers or peer_cookies):
        return None
    return owner_headers, owner_cookies, peer_headers, peer_cookies


def _sync_peer_session_from_config(state: ProgramState, config: AgentConfig) -> None:
    """Copy config.peer_cookie onto state.peer_* when AutoRegister only set the flag."""
    from shroodler.idor_engine import session_from_auth_line

    if dict(getattr(state, "peer_headers", None) or {}) or dict(
        getattr(state, "peer_cookies", None) or {}
    ):
        return
    headers, cookies = session_from_auth_line(config.peer_cookie or "")
    if headers or cookies:
        state.peer_headers = headers
        state.peer_cookies = cookies


def _pending_auto_register(state: ProgramState, config: AgentConfig) -> bool:
    if not getattr(config, "auto_register", True):
        return False
    if getattr(config, "_auto_register_done", False):
        return False
    if not _has_owner_session(config):
        return False
    if _has_peer_session(config):
        return False
    from shroodler.second_account import detect_registration_url, peer_cookie_from_state

    return bool(peer_cookie_from_state(state) or detect_registration_url(state))


def _pending_login(state: ProgramState, config: AgentConfig) -> bool:
    if not str(getattr(config, "login_recipe", None) or "").strip():
        return False
    if getattr(state, "login_failed", False):
        return False
    if getattr(config, "_login_done", False):
        return False
    return True


def _cookie_payload(raw: str) -> str:
    text = (raw or "").strip()
    lowered = text.lower()
    if lowered.startswith("cookie:"):
        return text.split(":", 1)[1].strip()
    if lowered.startswith("authorization:"):
        return ""
    return text


def _login_extra_headers(state: ProgramState, config: AgentConfig) -> dict[str, str]:
    extra = {
        str(k): str(v)
        for k, v in dict(getattr(state, "login_headers", None) or {}).items()
    }
    owner, _peer = _probe_auth_headers(config)
    if owner.lower().startswith("authorization:") and "Authorization" not in extra:
        extra["Authorization"] = owner.split(":", 1)[1].strip()
    return extra


def _merged_owner_cookie(state: ProgramState, config: AgentConfig) -> str:
    owner, _peer = _probe_auth_headers(config)
    parts: list[str] = []
    payload = _cookie_payload(owner)
    if payload:
        parts.append(payload)
    for name, value in dict(getattr(state, "login_cookies", None) or {}).items():
        if name:
            parts.append(f"{name}={value}")
    return "; ".join(parts)


def _merged_peer_identity(
    state: ProgramState, config: AgentConfig
) -> tuple[str, dict[str, str]]:
    """Build (peer_cookie_header, peer_extra_headers) for the impact proof.

    Returns ("", {}) when no peer identity is configured, so the IDOR fetch-and-
    diff proof simply skips rather than guessing.
    """
    sessions = _resolve_idor_sessions(state, config)
    if not sessions:
        return "", {}
    _oh, _oc, peer_headers, peer_cookies = sessions
    parts: list[str] = []
    extra: dict[str, str] = {}
    for key, value in dict(peer_headers or {}).items():
        if str(key).lower() == "cookie" and value:
            parts.append(str(value))
        elif value:
            extra[str(key)] = str(value)
    if peer_cookies:
        parts.append("; ".join(f"{k}={v}" for k, v in peer_cookies.items() if k))
    return "; ".join(p for p in parts if p), extra


def _owner_auth_line(state: ProgramState, config: AgentConfig) -> str:
    extra = _login_extra_headers(state, config)
    owner, _peer = _probe_auth_headers(config)
    if owner.lower().startswith("authorization:"):
        return owner
    auth = extra.get("Authorization") or ""
    if not auth:
        return ""
    if auth.lower().startswith("authorization:"):
        return auth
    return f"Authorization: {auth}"


def _owner_for_probes(state: ProgramState, config: AgentConfig) -> str:
    merged = _merged_owner_cookie(state, config)
    if merged:
        return merged
    auth = _owner_auth_line(state, config)
    if auth:
        return auth
    owner, _peer = _probe_auth_headers(config)
    return owner


def _apply_login_to_config(config: AgentConfig, result: Any) -> None:
    cookies = dict(getattr(result, "inject_cookies", None) or {})
    headers = dict(getattr(result, "inject_headers", None) or {})
    if cookies and not str(config.owner_cookie or "").strip():
        config.owner_cookie = "; ".join(f"{k}={v}" for k, v in cookies.items() if k)
    auth = headers.get("Authorization") or ""
    if auth and not str(config.owner_cookie or "").strip():
        if auth.lower().startswith("authorization:"):
            config.owner_cookie = auth
        else:
            config.owner_cookie = f"Authorization: {auth}"


def _apply_peer_to_config(config: AgentConfig, result: Any) -> None:
    cookies = dict(getattr(result, "inject_cookies", None) or {})
    headers = dict(getattr(result, "inject_headers", None) or {})
    if cookies and not str(config.peer_cookie or "").strip():
        config.peer_cookie = "; ".join(f"{k}={v}" for k, v in cookies.items() if k)
    auth = headers.get("Authorization") or ""
    if auth and not str(config.peer_cookie or "").strip():
        if auth.lower().startswith("authorization:"):
            config.peer_cookie = auth
        else:
            config.peer_cookie = f"Authorization: {auth}"


def _make_reauth_callback(state: ProgramState, config: AgentConfig, pacer: Pacer):
    def _reauth() -> bool:
        path = str(getattr(config, "login_recipe", None) or "").strip()
        if not path:
            return False
        cap = max(0, int(getattr(config, "reauth_max_retries", 0) or 0))
        if cap <= 0:
            return False
        attempts = int(getattr(state, "reauth_attempts", 0) or 0)
        if attempts >= cap:
            return False
        state.reauth_attempts = attempts + 1
        from shroodler.login_executor import LoginExecutor, apply_session
        from shroodler.probes.common import update_probe_http_session

        executor = LoginExecutor(pacer=pacer)
        result = executor.run_sync(path, seed=config.target)
        if not result.success:
            return False
        apply_session(state, result.inject_headers, result.inject_cookies)
        _apply_login_to_config(config, result)
        token = (result.extracted.get("access_token") or result.extracted.get("token") or "")
        if token:
            state.bearer_token = token
        elif result.inject_headers.get("Authorization"):
            state.bearer_token = (
                result.inject_headers["Authorization"].split(None, 1)[-1].strip()
            )
        owner = _owner_for_probes(state, config)
        update_probe_http_session(
            extra_headers=dict(result.inject_headers or {}),
            extra_cookies=dict(result.inject_cookies or {}),
            owner_cookie_header=owner,
        )
        return True

    return _reauth


def _bind_probe_session(state: ProgramState, config: AgentConfig, pacer: Pacer):
    from shroodler.probes.common import probe_http_session

    owner = _owner_for_probes(state, config)
    extra_headers = _login_extra_headers(state, config)
    extra_cookies = dict(getattr(state, "login_cookies", None) or {})
    callback = getattr(state, "reauth_callback", None)
    if callback is None and str(getattr(config, "login_recipe", None) or "").strip():
        if int(getattr(config, "reauth_max_retries", 0) or 0) > 0:
            callback = _make_reauth_callback(state, config, pacer)
            state.reauth_callback = callback
    return probe_http_session(
        extra_headers=extra_headers,
        extra_cookies=extra_cookies,
        reauth=callback,
        owner_cookie_header=owner,
    )


def _ghost_path_pattern(url: str) -> str:
    """Origin-agnostic path pattern: braces, UUIDs, and digits collapse to {id}."""
    from urllib.parse import urlparse

    from shroodler.llm_agent.probe_memory import normalise_url

    raw = (url or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "http://ghost.invalid" + (raw if raw.startswith("/") else "/" + raw)
    try:
        parsed = urlparse(raw)
    except ValueError:
        return ""
    braced = _PLACEHOLDER_RE.sub("{id}", parsed.path or "")
    dummy = parsed._replace(
        scheme="http",
        netloc="ghost.invalid",
        path=braced,
        query="",
        fragment="",
    ).geturl()
    try:
        norm = normalise_url(dummy)
    except Exception:  # noqa: BLE001
        norm = dummy
    try:
        path = urlparse(norm).path or ""
    except ValueError:
        path = braced
    parts: list[str] = []
    for seg in path.split("/"):
        if not seg:
            continue
        if _PLACEHOLDER_RE.fullmatch(seg) or seg.isdigit():
            parts.append("{id}")
        else:
            parts.append(seg)
    return "/" + "/".join(parts) if parts else "/"


def _params_missing(meta: dict | None) -> bool:
    if not isinstance(meta, dict):
        return True
    if "params" not in meta:
        return True
    return not meta.get("params")


def _infer_ghost_params(url: str) -> list[dict]:
    from shroodler.probes.common import normalize_params, params_from_url

    params = normalize_params([], url=url)
    seen = {item["name"] for item in params}
    for item in params_from_url(url):
        if item["name"] not in seen:
            params.append(item)
            seen.add(item["name"])
    return params


def _absolute_ghost_url(url: str, target: str) -> str:
    from urllib.parse import urljoin

    text = (url or "").strip()
    if not text:
        return ""
    if text.startswith(("http://", "https://")):
        return text
    base = target if str(target).endswith("/") else str(target or "") + "/"
    return urljoin(base, text)


def _maybe_hydrate_ghost_routes(state: ProgramState, config: AgentConfig) -> None:
    if getattr(config, "_ghost_hydrate_done", False):
        return
    has_oa = bool(
        getattr(state, "openapi_spec_url", None)
        or getattr(state, "openapi_endpoints", None)
    )
    has_js = False
    for meta in (state.endpoints or {}).values():
        if isinstance(meta, dict) and meta.get("source") == "js-analysis":
            if _params_missing(meta):
                has_js = True
                break
    if not (has_oa or has_js):
        return
    _hydrate_ghost_routes(state, config)


def _hydrate_ghost_routes(state: ProgramState, config: AgentConfig) -> None:
    """Attach OpenAPI / inferred params onto ghost routes so active probes run.

    Runs once per agent config. OpenAPI path templates are matched against
    concrete JS-analysis URLs via ``normalise_url`` (plus remaining digit
    segments). Numeric path IDs get a synthetic ``id`` param when no spec
    match exists.
    """
    config._ghost_hydrate_done = True
    now = now_iso()
    target = str(getattr(config, "target", "") or "")
    oa_by_pattern: dict[str, dict[str, Any]] = {}

    for row in state.openapi_endpoints or []:
        if not isinstance(row, dict):
            continue
        raw_url = str(row.get("url") or "")
        if not raw_url:
            continue
        url = _absolute_ghost_url(raw_url, target) or raw_url
        params = list(row.get("params") or [])
        program._upsert_endpoint(
            state,
            url,
            now,
            method=row.get("method"),
            params=params,
            source="openapi",
        )
        key = program._endpoint_key(url)
        meta = state.endpoints.get(key)
        if meta is not None and row.get("auth_required"):
            meta["auth_required"] = True
        pattern = _ghost_path_pattern(url)
        if pattern:
            # Prefer a row that actually has params when several share a path.
            prev = oa_by_pattern.get(pattern)
            if prev is None or (params and not (prev.get("params") or [])):
                oa_by_pattern[pattern] = {**row, "url": url}

    for url, meta in list(state.endpoints.items()):
        if not isinstance(meta, dict):
            continue
        if meta.get("source") != "js-analysis":
            continue
        if not _params_missing(meta):
            continue
        pattern = _ghost_path_pattern(url)
        oa = oa_by_pattern.get(pattern) if pattern else None
        method = meta.get("method")
        auth_required = bool(meta.get("auth_required"))
        if oa and (oa.get("params") or []):
            inferred = {p["name"]: p for p in _infer_ghost_params(url)}
            incoming = []
            for item in oa.get("params") or []:
                row = dict(item)
                inf = inferred.get(str(row.get("name") or ""))
                if inf and not row.get("value") and inf.get("value"):
                    row["value"] = inf["value"]
                incoming.append(row)
            seen = {str(r.get("name") or "") for r in incoming}
            for inf in inferred.values():
                if inf["name"] not in seen:
                    incoming.append(inf)
            method = oa.get("method") or method
            auth_required = auth_required or bool(oa.get("auth_required"))
        else:
            incoming = _infer_ghost_params(url)
        if not incoming:
            continue
        last_seen = str(meta.get("last_seen") or "") or now
        program._upsert_endpoint(
            state,
            url,
            last_seen,
            method=method,
            params=incoming,
        )
        stored = state.endpoints.get(program._endpoint_key(url))
        if stored is not None and auth_required:
            stored["auth_required"] = True


def decide_next_action(
    state: ProgramState,
    config: AgentConfig,
    crawl_stall_count: int = 0,
) -> AgentAction | None:
    """Priority: Login > TLSCheck > Crawl > JSAnalysis > Diff > WafDetect >
    OpenApiDiscover > AutoRegister > AuthzDiff > IDORScan > WriteAuthz >
    PeerWrite > ContentDiscover > Probe > OpenApiProbe > BusinessLogic >
    Chain > Report.

    WafDetect sits after Diff (not immediately after TLSCheck) so existing
    decide_next_action tests that expect Crawl/JS/Diff as the next live action
    still pass. It still runs before Probe so mutate_payload() applies. Dry-run
    plans skip it: nearly every unit test uses dry_run=True via _config(), and
    inserting a default-on action would change those return values.
    """
    from urllib.parse import urlparse

    if _pending_login(state, config):
        return LoginAction()

    if config.run_tls_check and not getattr(config, "_tls_check_done", False):
        if urlparse(config.target).scheme == "https":
            return TLSCheckAction()
        config._tls_check_done = True

    crawl_urls = crawl_coverage_gaps(state, config)
    if crawl_urls and crawl_stall_count < _CRAWL_STALL_LIMIT:
        return CrawlAction(urls=crawl_urls)

    js_urls = _js_urls_for_analysis(state)
    if (
        config.run_js_analysis
        and not getattr(config, "_js_analysis_done", False)
        and js_urls
    ):
        return JSAnalysisAction(urls=js_urls)

    if _should_run_diff(state, config):
        return DiffAction()

    # After Diff / Crawl / JS, before OpenAPI and Probe. Skipped in dry-run so
    # existing decide_next_action tests keep their observed sequence.
    if (
        getattr(config, "run_waf_detect", True)
        and not getattr(config, "_waf_detect_done", False)
        and not getattr(config, "dry_run", False)
    ):
        return WafDetectAction()

    if (
        config.run_openapi_discovery
        and not getattr(config, "_openapi_discover_done", False)
        and not state.openapi_spec_url
    ):
        return OpenApiDiscoverAction()

    if _pending_auto_register(state, config):
        return AutoRegisterAction()

    authz_urls: list[str] = []
    object_ids: list[str] = []
    write_endpoints: list[dict] = []
    if (config.higher_priv_jar and config.lower_priv_jar) or (
        config.higher_priv_jar and (config.peer_cookie or "").strip()
    ):
        authz_urls = _untested_authz_urls(state, config)
    if config.owner_cookie and config.peer_cookie:
        object_ids = _pending_peer_write_ids(state, config)
        if not getattr(config, "_write_authz_done", False):
            write_endpoints = _ensure_write_authz_endpoints(config)

    if config.llm_triage and (authz_urls or object_ids):
        from shroodler.llm_triage import triage_leads

        triage = triage_leads(state, object_ids, authz_urls, config)
        object_ids = list(triage.ranked_ids)
        authz_urls = list(triage.ranked_urls)
        emit_log_entry(
            {
                "iteration": int(getattr(config, "_iteration", 0) or 0),
                "triage_rationale": triage.rationale,
                "used_llm": triage.used_llm,
            }
        )

    if authz_urls:
        return AuthzDiffAction(urls=authz_urls)
    if _pending_idor_scan(state, config):
        return IDORScanAction()
    if write_endpoints:
        return WriteAuthzAction(endpoints=write_endpoints)
    if object_ids:
        return PeerWriteAction(object_ids=object_ids)

    if config.run_content_discovery and not getattr(config, "_content_discover_done", False):
        return ContentDiscoverAction()

    # After OpenAPI discover has had a chance to run (this branch is only
    # reached when it already returned, is disabled, or spec_url is set).
    # Also hydrates JS-only ghost routes when no spec was found.
    _maybe_hydrate_ghost_routes(state, config)

    if config.run_probes:
        probe_urls = _untested_probe_urls(state, config)
        if probe_urls:
            return ProbeAction(urls=probe_urls)

    if config.run_openapi_probes:
        oa_endpoints = _untested_openapi_endpoints(state, config)
        if oa_endpoints:
            return OpenApiProbeAction(endpoints=oa_endpoints)

    if _pending_business_logic(config):
        return BusinessLogicAction()

    if _pending_chains(state, config):
        return ChainAction()

    if _confirmed_findings(state):
        return ReportAction()
    return None


def emit_log_entry(entry: dict[str, Any], *, stream: Any | None = None) -> None:
    print(json.dumps(entry, default=str), file=stream or sys.stderr, flush=True)


def _finding_key(item: Any) -> tuple[str, str]:
    return (str(getattr(item, "id", "") or ""), str(getattr(item, "url", "") or ""))


def _attach_live_details(
    result: dict[str, Any],
    state: ProgramState,
    *,
    before_findings: set[tuple[str, str]],
    before_endpoints: set[str],
) -> None:
    """Add finding id/url and new endpoint URLs so Discord live logs are useful."""
    if "findings" not in result:
        briefs: list[dict[str, str]] = []
        for item in state.findings:
            if _finding_key(item) in before_findings:
                continue
            briefs.append(
                {
                    "id": str(getattr(item, "id", "") or "unknown"),
                    "severity": str(getattr(item, "severity", "") or "info"),
                    "url": str(getattr(item, "url", "") or ""),
                }
            )
        if briefs:
            result["findings"] = briefs
    if "urls" not in result:
        new_urls = [url for url in state.endpoints if url not in before_endpoints]
        if new_urls:
            result["urls"] = new_urls


def _merge_findings(state: ProgramState, findings: list[Any]) -> int:
    from shroodler.engagement_history import is_suppressed

    seen = {(f.id, f.url) for f in state.findings}
    added = 0
    for raw in findings or []:
        parsed: Finding | None
        if isinstance(raw, Finding):
            parsed = raw
        elif isinstance(raw, dict):
            parsed = program._finding_from_dict(raw)
        else:
            continue
        if parsed is None:
            continue
        if is_suppressed(state, parsed.id, parsed.url):
            continue
        key = (parsed.id, parsed.url)
        if key in seen:
            continue
        seen.add(key)
        state.findings.append(parsed)
        added += 1
    return added


def _cookie_header_from_jar(path: str, target: str) -> str:
    from shroodler.cookie_source import resolve_cookie_header

    return resolve_cookie_header(path=path, origin_url=target)


def _auth_header_for_diff(config: AgentConfig, role: str) -> str:
    raw = config.higher_priv_jar if role == "higher" else config.lower_priv_jar
    override = config.owner_cookie if role == "higher" else config.peer_cookie
    if override and override.strip().lower().startswith("authorization:"):
        return override.strip()
    if raw:
        return _cookie_header_from_jar(raw, config.target)
    return (override or "").strip()


def _probe_auth_headers(config: AgentConfig) -> tuple[str, str]:
    """Owner + peer Cookie/Authorization lines for active probes."""
    try:
        owner = _auth_header_for_diff(config, "higher")
    except Exception:  # noqa: BLE001 - probes must fail closed
        owner = (config.owner_cookie or "").strip()
    try:
        peer = _auth_header_for_diff(config, "lower")
    except Exception:  # noqa: BLE001
        peer = (config.peer_cookie or "").strip()
    return owner, peer


def _has_unresolved_placeholder(url: str) -> bool:
    return bool(_PLACEHOLDER_RE.search(url or ""))


def _js_urls_for_analysis(state: ProgramState) -> list[str]:
    """Prefer state.js_urls; otherwise collect script srcs from crawl snapshots."""
    from urllib.parse import urljoin

    seen: set[str] = set()
    out: list[str] = []

    def add(raw: str) -> None:
        url = (raw or "").strip()
        if not url or url in seen:
            return
        seen.add(url)
        out.append(url)

    for item in getattr(state, "js_urls", None) or []:
        add(str(item))
    if out:
        return out
    for scan in state.scans or []:
        if not isinstance(scan, dict):
            continue
        for page in scan.get("pages") or []:
            if not isinstance(page, dict):
                continue
            base = str(page.get("url") or "")
            for key in ("js_files", "script_srcs", "scripts", "js_urls"):
                val = page.get(key)
                items = val if isinstance(val, list) else ([val] if val else [])
                for raw in items:
                    if not raw:
                        continue
                    text = str(raw).strip()
                    add(urljoin(base, text) if base else text)
    for bundle in getattr(state, "js_bundles", None) or []:
        if isinstance(bundle, dict) and bundle.get("url"):
            add(str(bundle["url"]))
        elif isinstance(bundle, str) and bundle.startswith(("http://", "https://")):
            add(bundle)
    return out


def _describe_action(action: AgentAction) -> dict[str, Any]:
    if isinstance(action, LoginAction):
        return {"login": True}
    if isinstance(action, TLSCheckAction):
        return {"tls_check": True}
    if isinstance(action, WafDetectAction):
        return {"waf_detect": True}
    if isinstance(action, ContentDiscoverAction):
        return {"content_discover": True}
    if isinstance(action, CrawlAction):
        return {"urls": list(action.urls)}
    if isinstance(action, JSAnalysisAction):
        return {"js_analysis": True, "urls": list(action.urls)}
    if isinstance(action, DiffAction):
        return {"diff": True}
    if isinstance(action, OpenApiDiscoverAction):
        return {"openapi_discover": True}
    if isinstance(action, AutoRegisterAction):
        return {"auto_register": True}
    if isinstance(action, AuthzDiffAction):
        return {"urls": list(action.urls)}
    if isinstance(action, IDORScanAction):
        return {"idor_scan": True}
    if isinstance(action, WriteAuthzAction):
        return {
            "endpoints": [
                {"method": p.get("method"), "url": p.get("url")} for p in action.endpoints
            ]
        }
    if isinstance(action, PeerWriteAction):
        return {"object_ids": list(action.object_ids)}
    if isinstance(action, ProbeAction):
        return {"urls": list(action.urls)}
    if isinstance(action, OpenApiProbeAction):
        return {
            "endpoints": [
                {"method": p.get("method"), "url": p.get("url")} for p in action.endpoints
            ]
        }
    if isinstance(action, BusinessLogicAction):
        return {"business_logic": True}
    if isinstance(action, ChainAction):
        return {"chain": True}
    if isinstance(action, ReportAction):
        return {"report": True}
    return {}


def _llm_cost_cap_finding(config: AgentConfig) -> Finding:
    cost = float(getattr(config, "_llm_cost_usd", 0.0) or 0.0)
    cap = float(config.llm_agent_max_cost_usd)
    return Finding(
        id="llm-cost-cap-reached",
        severity="info",
        category="scan-note",
        url=str(config.target or ""),
        description=(
            f"LLM agent stopped: estimated cost ${cost:.4f} exceeded "
            f"cap ${cap:.2f}."
        ),
        evidence=f"cost_usd={cost:.6f} cap_usd={cap} model={config.llm_agent_model}",
        confidence="heuristic",
    )


def _history_from_action(
    iteration: int,
    action: AgentAction,
    entry: dict[str, Any],
    *,
    reasoning: str = "",
) -> Any:
    from shroodler.llm_agent.history import HistoryEntry

    described = _describe_action(action)
    params: dict[str, Any] = {}
    urls = described.get("urls") or []
    if urls:
        params["url"] = urls[0]
    result = entry.get("result") if isinstance(entry.get("result"), dict) else {}
    added = int((result or {}).get("findings_added") or 0)
    return HistoryEntry(
        iteration=iteration,
        action=type(action).__name__,
        params=params,
        reasoning=reasoning,
        findings_added=added,
        summary=str((result or {}).get("summary") or type(action).__name__),
    )


@dataclass
class _LlmStep:
    stop: bool = False
    executed: bool = False
    done: bool = False
    fallback_action: AgentAction | None = None
    entry: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


def _probe_memory_db_path(config: AgentConfig) -> str:
    """Prefer program_dir/program/probe_memory.db; else a temp file."""
    import tempfile

    slug = str(getattr(config, "program", "") or "")
    explicit = getattr(config, "program_dir", None)
    if explicit:
        base = Path(explicit)
        if slug:
            return str(base / slug / "probe_memory.db")
        return str(base / "probe_memory.db")
    if slug:
        try:
            return str(program.program_dir(slug) / "probe_memory.db")
        except ValueError:
            pass
    return str(Path(tempfile.gettempdir()) / "shroodler-probe-memory.db")


def _llm_agent_step(
    state: ProgramState,
    config: AgentConfig,
    pacer: Pacer,
    iteration: int,
    history: list[Any],
    crawl_stall_count: int,
    probe_memory: Any = None,
) -> _LlmStep:
    """One LLM iteration. Fallback uses decide_next_action; never raises."""
    from shroodler.llm_agent.context import build_context
    from shroodler.llm_agent.executor import execute_tool
    from shroodler.llm_agent.guardrails import check_guardrails
    from shroodler.llm_agent.history import HistoryEntry, trim_history
    from shroodler.llm_agent.planner import estimate_cost_usd, plan_next_action
    from shroodler.llm_agent.tools import TOOLS

    cost = float(getattr(config, "_llm_cost_usd", 0.0) or 0.0)
    cap = float(config.llm_agent_max_cost_usd)
    if cost > cap:
        added = _merge_findings(state, [_llm_cost_cap_finding(config)])
        if not config.dry_run:
            program.save(state)
        return _LlmStep(
            stop=True,
            entry={
                "iteration": iteration,
                "action": "llm-cost-cap-reached",
                "reasoning": "estimated API cost exceeded cap",
                "findings_added": added,
            },
        )

    ctx = build_context(state, state.findings, history, config)
    decision = plan_next_action(
        ctx, TOOLS, config, history, probe_memory=probe_memory
    )
    delta = estimate_cost_usd(
        decision.model, decision.input_tokens, decision.output_tokens
    )
    config._llm_cost_usd = cost + delta

    if float(config._llm_cost_usd) > cap:
        added = _merge_findings(state, [_llm_cost_cap_finding(config)])
        if not config.dry_run:
            program.save(state)
        return _LlmStep(
            stop=True,
            entry={
                "iteration": iteration,
                "action": "llm-cost-cap-reached",
                "reasoning": decision.reasoning or "estimated API cost exceeded cap",
                "findings_added": added,
            },
        )

    blocked_reason = ""
    use_fallback = bool(decision.fallback or not decision.action)
    if use_fallback:
        blocked_reason = decision.fallback_reason or "invalid planner output"
    else:
        guard = check_guardrails(decision, history, state, config)
        if not guard.allowed:
            use_fallback = True
            blocked_reason = guard.reason
    config._llm_last_guardrail = blocked_reason

    if use_fallback:
        emit_log_entry(
            {
                "warning": "llm-agent-fallback",
                "iteration": iteration,
                "reason": blocked_reason,
            }
        )
        action = decide_next_action(state, config, crawl_stall_count)
        return _LlmStep(fallback_action=action)

    if config.dry_run:
        entry = {
            "iteration": iteration,
            "action": decision.action,
            "reasoning": decision.reasoning,
            "findings_added": 0,
            "dry_run": True,
            "params": dict(decision.params or {}),
        }
        history.append(
            HistoryEntry(
                iteration=iteration,
                action=str(decision.action),
                params=dict(decision.params or {}),
                reasoning=decision.reasoning,
                findings_added=0,
                summary="dry_run",
            )
        )
        kept = trim_history(list(history), 10)
        history.clear()
        history.extend(kept)
        return _LlmStep(executed=True, entry=entry)

    try:
        result = execute_tool(
            decision,
            state,
            config,
            None,
            None,
            pacer,
            probe_memory=probe_memory,
        )
    except Exception as exc:  # noqa: BLE001
        message = f"{type(exc).__name__}: {exc}"
        return _LlmStep(
            executed=True,
            entry={
                "iteration": iteration,
                "action": decision.action,
                "reasoning": decision.reasoning,
                "findings_added": 0,
                "error": message,
            },
            errors=[message],
        )
    program.save(state)
    added = int(result.findings_added or 0)
    entry = {
        "iteration": iteration,
        "action": decision.action,
        "reasoning": decision.reasoning,
        "findings_added": added,
        "result": result.raw_output,
        "summary": result.summary,
    }
    from shroodler.llm_agent.context import trim_observation

    history.append(
        HistoryEntry(
            iteration=iteration,
            action=str(decision.action),
            params=dict(decision.params or {}),
            reasoning=decision.reasoning,
            findings_added=added,
            summary=result.summary,
            observation=trim_observation(result.raw_output),
        )
    )
    kept = trim_history(list(history), 10)
    history.clear()
    history.extend(kept)
    errors = []
    if isinstance(result.raw_output, dict):
        for err in result.raw_output.get("errors") or []:
            errors.append(str(err))
    return _LlmStep(
        executed=True,
        done=bool(result.done),
        entry=entry,
        errors=errors,
    )


def run_agent(config: AgentConfig) -> AgentResult:
    if config.llm_agent:
        from shroodler.llm_provider import llm_api_key_env, provider_requires_api_key

        provider = getattr(config, "llm_provider", "anthropic")
        env_name = llm_api_key_env(provider)
        if provider_requires_api_key(provider) and not os.environ.get(env_name):
            return AgentResult(
                iterations=0,
                confirmed=0,
                log=[],
                state_path="",
                errors=[f"--llm-agent requires {env_name}"],
            )
    probe_memory = None
    collab = None
    if config.llm_agent:
        from shroodler.llm_agent.probe_memory import ProbeMemory

        probe_memory = ProbeMemory(_probe_memory_db_path(config))
    try:
        if getattr(config, "oob", False):
            from shroodler.oob import set_active, start_from_config

            collab = start_from_config(config)
            config._oob = collab
            set_active(collab)
        return _run_agent_body(config, probe_memory)
    finally:
        if collab is not None:
            try:
                from shroodler.oob import set_active as _clear_oob

                _clear_oob(None)
                collab.stop()
            except Exception:  # noqa: BLE001
                pass
            config._oob = None
        if probe_memory is not None:
            probe_memory.close()


def _run_agent_body(config: AgentConfig, probe_memory: Any = None) -> AgentResult:
    state = program.load(config.program)
    assert_target_in_scope(state, config.target)
    state.oob = getattr(config, "_oob", None)
    path = str(program.state_path(state.slug))
    log: list[dict[str, Any]] = []
    errors: list[str] = []
    consecutive_errors = 0
    _crawl_stall_count = 0
    pacer = Pacer(0.0) if getattr(config, "aggressive", False) else _new_pacer()
    llm_history: list[Any] = []
    config._llm_cost_usd = 0.0
    config._llm_last_guardrail = ""
    if config.write_authz_spec:
        _ensure_write_authz_endpoints(config)

    config._prev_endpoints = copy.deepcopy(state.endpoints)
    config._run_started_at = now_utc().isoformat()
    config._endpoint_count_at_start = len(state.endpoints)
    config._crawled_this_run = False
    config._diff_done = False
    config._business_logic_done = False
    config._chain_done = False
    config._openapi_discover_done = False
    config._tls_check_done = False
    config._waf_detect_done = False
    config._content_discover_done = False
    config._js_analysis_done = False
    config._idor_scan_done = False

    mutated = False
    if config.reprobe:
        mutated = _reset_tested_payload(state) > 0 or mutated
    mutated = _backfill_authz_confidence(state) > 0 or mutated
    if mutated:
        program.save(state)

    if config.run_discovery:
        from dataclasses import asdict

        from shroodler.discovery import DiscoveryConfig, discover

        disc = discover(
            state,
            config.target,
            DiscoveryConfig(target=config.target, dry_run=config.dry_run),
        )
        emit_log_entry({"pre_loop": "discovery", "result": asdict(disc)})

    # Content-discovery (sensitive-path exposure: .git/.env/backups/config/admin)
    # is not an LLM tool, so in --llm-agent mode it would otherwise run only
    # opportunistically via the deterministic fallback -- meaning a critical
    # exposure like an open .git directory gets found inconsistently between
    # runs. Force it once up front for every agent scan, like a human doing
    # recon. The deterministic (non-LLM) path already runs it in priority order.
    if (
        config.llm_agent
        and config.run_content_discovery
        and not config.dry_run
        and not getattr(config, "_content_discover_done", False)
    ):
        try:
            cd = _execute_content_discover(ContentDiscoverAction(), state, config, pacer)
            program.save(state)
            emit_log_entry({"pre_loop": "content-discover", "result": cd})
        except Exception as exc:  # noqa: BLE001 - recon must never break the run
            emit_log_entry(
                {"pre_loop": "content-discover", "error": f"{type(exc).__name__}: {exc}"}
            )

    for i in range(max(0, int(config.max_iterations))):
        config._iteration = i + 1  # used by decide_next_action triage logs
        if config.llm_agent:
            step = _llm_agent_step(
                state,
                config,
                pacer,
                i + 1,
                llm_history,
                _crawl_stall_count,
                probe_memory=probe_memory,
            )
            if step.stop:
                if step.entry:
                    log.append(step.entry)
                    emit_log_entry(step.entry)
                errors.extend(step.errors)
                break
            if step.executed:
                log.append(step.entry)
                emit_log_entry(step.entry)
                consecutive_errors = 0
                errors.extend(step.errors)
                if step.done:
                    break
                continue
            action = step.fallback_action
        else:
            action = decide_next_action(state, config, _crawl_stall_count)
        if action is None:
            break
        entry: dict[str, Any] = {
            "iteration": i + 1,
            "action": type(action).__name__,
        }
        if config.dry_run:
            entry["dry_run"] = True
            entry.update(_describe_action(action))
            consecutive_errors = 0
        else:
            try:
                before_findings = {_finding_key(item) for item in state.findings}
                before_endpoints = set(state.endpoints)
                result = execute_action(action, state, config, pacer=pacer)
                if isinstance(result, dict):
                    _attach_live_details(
                        result,
                        state,
                        before_findings=before_findings,
                        before_endpoints=before_endpoints,
                    )
                program.save(state)
                entry["result"] = result
                consecutive_errors = 0
                for err in result.get("errors") or []:
                    errors.append(str(err))
                if isinstance(action, CrawlAction):
                    pages = int(result.get("pages_crawled") or 0)
                    if pages == 0:
                        _crawl_stall_count += 1
                    else:
                        _crawl_stall_count = 0
            except Exception as exc:  # noqa: BLE001 - loop must not crash
                consecutive_errors += 1
                message = f"{type(exc).__name__}: {exc}"
                entry["error"] = message
                errors.append(message)
                if consecutive_errors >= config.max_iterations:
                    log.append(entry)
                    emit_log_entry(entry)
                    break
        if config.llm_agent:
            entry.setdefault(
                "reasoning",
                str(getattr(config, "_llm_last_guardrail", "") or "fallback"),
            )
            result = entry.get("result") if isinstance(entry.get("result"), dict) else {}
            entry.setdefault(
                "findings_added",
                int((result or {}).get("findings_added") or 0),
            )
            llm_history.append(
                _history_from_action(
                    i + 1,
                    action,
                    entry,
                    reasoning=str(entry.get("reasoning") or ""),
                )
            )
            from shroodler.llm_agent.history import trim_history as _trim

            kept = _trim(list(llm_history), 10)
            llm_history.clear()
            llm_history.extend(kept)
        log.append(entry)
        emit_log_entry(entry)
        if isinstance(action, ReportAction):
            break

    if getattr(config, "llm_verify", False):
        _run_llm_verify(state, config, pacer, log)

    if getattr(config, "prove_impact", False) and not config.dry_run:
        from shroodler.impact import annotate_impact

        peer_cookie, peer_extra = _merged_peer_identity(state, config)
        proven = annotate_impact(
            state.findings,
            cookie_header=_merged_owner_cookie(state, config),
            peer_cookie_header=peer_cookie,
            peer_headers=peer_extra,
            pacer=pacer,
            prove_xss=True,
        )
        if proven:
            emit_log_entry({"impact": "proven", "count": proven})
            program.save(state)

    confirmed = _confirmed_findings(state)
    if not config.dry_run:
        state.previous_endpoints = copy.deepcopy(config._prev_endpoints)
        program.record_run_summary(
            state,
            {
                "started_at": getattr(config, "_run_started_at", None) or now_utc().isoformat(),
                "iterations": len(log),
                "confirmed": len(confirmed),
                "new_endpoints": max(
                    0,
                    len(state.endpoints)
                    - int(getattr(config, "_endpoint_count_at_start", 0) or 0),
                ),
            },
        )
        program.save(state)
    return AgentResult(
        iterations=len(log),
        confirmed=len(confirmed),
        log=log,
        state_path=path,
        errors=errors,
    )


from shroodler.agent_exec import (  # noqa: E402
    _execute_content_discover,
    _run_llm_verify,
    execute_action,
)
