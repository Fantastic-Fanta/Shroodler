"""Autonomous engagement loop over per-program state.

Reads ~/.shroodler/programs/<slug>/state.json, picks the next highest-value
action (login → tls-check → crawl → js-analysis → diff → openapi-discover →
auto-register → authz-diff → idor-scan → write-authz → peer-write → content-discover →
probe → openapi-probe → business-logic → chain → report),
executes it through existing Shroodler APIs, merges results, and repeats until
the iteration budget is exhausted or there is nothing left to do.

No new dependencies. Single-threaded. Dry-run makes no HTTP requests.
"""

from __future__ import annotations

import asyncio
import copy
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from shroodler import program
from shroodler.models import Finding
from shroodler.pacer import Pacer
from shroodler.program import ProgramState, object_ids_flat, url_to_pattern
from shroodler.urls import is_loopback_or_local, origin as origin_of, same_origin

_STALE_AFTER = timedelta(hours=24)
_DEFAULT_RATE_CEILING = 0.1  # 100 ms between HTTP requests if no guardrail
_CRAWL_STALL_LIMIT = 3
_PLACEHOLDER_RE = re.compile(r"\{[^{}]+\}")


@dataclass
class AgentConfig:
    program: str
    target: str
    max_iterations: int = 10
    max_pages_per_crawl: int = 30
    login_recipe: str | None = None
    reauth_max_retries: int = 3
    higher_priv_jar: str | None = None
    lower_priv_jar: str | None = None
    owner_cookie: str | None = None
    peer_cookie: str | None = None
    dry_run: bool = False
    llm_triage: bool = False  # opt-in; requires the provider API key in env
    run_discovery: bool = False  # run discover() before the first iteration
    ignore_robots: bool = False  # bypass robots.txt (use for API-first targets)
    write_authz_spec: str | None = None
    write_authz_endpoints: list[dict] | None = None
    run_probes: bool = False  # opt-in; default off
    probe_sqli: bool = True
    probe_xss: bool = True
    probe_path_traversal: bool = True
    probe_jwt: bool = True
    probe_idor: bool = True
    run_ssrf: bool = True
    run_open_redirect: bool = True
    run_host_header: bool = True
    run_ssti: bool = True
    run_xxe: bool = True
    run_graphql: bool = True
    auto_register: bool = True
    reprobe: bool = False  # reset tested_payload before the loop
    run_diff: bool = False  # opt-in; also auto-runs when a previous run exists
    run_business_logic: bool = False  # --llm-business-logic
    chain_specs: list[str] = field(default_factory=list)
    run_openapi_discovery: bool = True  # on by default; mapping, not probing
    run_openapi_probes: bool = True
    run_dom_xss: bool = False  # opt-in; headless / slow
    run_crlf: bool = True
    run_prototype_pollution: bool = True
    run_content_discovery: bool = True
    run_tls_check: bool = True
    run_rate_limit: bool = True
    run_mass_assignment: bool = True
    run_smuggling: bool = False  # opt-in; aggressive
    run_websocket: bool = True
    allow_external: bool = False
    scope_file: str | None = None
    llm_agent: bool = False  # --llm-agent; requires the provider API key
    llm_provider: str = "anthropic"  # "anthropic" | "deepseek"
    llm_agent_model: str = "claude-sonnet-5"
    llm_agent_max_cost_usd: float = 5.0
    run_js_analysis: bool = True  # --no-js-analysis to skip
    idor_methods: list[str] = field(default_factory=lambda: ["GET"])
    peer_recipe: str | None = None


@dataclass
class LoginAction:
    pass


@dataclass
class TLSCheckAction:
    pass


@dataclass
class ContentDiscoverAction:
    pass


@dataclass
class CrawlAction:
    urls: list[str]


@dataclass
class JSAnalysisAction:
    urls: list[str] = field(default_factory=list)


@dataclass
class DiffAction:
    pass


@dataclass
class OpenApiDiscoverAction:
    pass


@dataclass
class AutoRegisterAction:
    pass


@dataclass
class AuthzDiffAction:
    urls: list[str]


@dataclass
class IDORScanAction:
    pass


@dataclass
class WriteAuthzAction:
    endpoints: list[dict]


@dataclass
class PeerWriteAction:
    object_ids: list[str]


@dataclass
class ProbeAction:
    urls: list[str]


@dataclass
class OpenApiProbeAction:
    endpoints: list[dict]


@dataclass
class BusinessLogicAction:
    pass


@dataclass
class ChainAction:
    pass


@dataclass
class ReportAction:
    pass


AgentAction = (
    LoginAction
    | TLSCheckAction
    | ContentDiscoverAction
    | CrawlAction
    | JSAnalysisAction
    | DiffAction
    | OpenApiDiscoverAction
    | AutoRegisterAction
    | AuthzDiffAction
    | IDORScanAction
    | WriteAuthzAction
    | PeerWriteAction
    | ProbeAction
    | OpenApiProbeAction
    | BusinessLogicAction
    | ChainAction
    | ReportAction
)


@dataclass
class AgentResult:
    iterations: int
    confirmed: int
    log: list[dict[str, Any]]
    state_path: str = ""
    errors: list[str] = field(default_factory=list)


def _now() -> datetime:
    return datetime.now(timezone.utc)


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
        dt = dt.replace(tzinfo=timezone.utc)
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
    from shroodler.scope import in_scope

    if in_scope(url, _scope_dict(state, config)):
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
    now = _now()
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


def _probe_rank(url: str, meta: dict | None) -> int:
    path = (url or "").lower()
    for i, token in enumerate(_PROBE_PRIORITY):
        if token in path:
            return i
    if (meta or {}).get("params"):
        return 50
    return 100


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


def decide_next_action(
    state: ProgramState,
    config: AgentConfig,
    crawl_stall_count: int = 0,
) -> AgentAction | None:
    """Priority: Login > TLSCheck > Crawl > JSAnalysis > Diff > OpenApiDiscover >
    AutoRegister > AuthzDiff > IDORScan > WriteAuthz > PeerWrite > ContentDiscover >
    Probe > OpenApiProbe > BusinessLogic > Chain > Report."""
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
    if config.higher_priv_jar and config.lower_priv_jar:
        authz_urls = _untested_authz_urls(state, config)
    elif config.higher_priv_jar and (config.peer_cookie or "").strip():
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


def _probe_params(url: str, meta: dict | None) -> tuple[str, list[dict]]:
    from shroodler.probes.common import normalize_params, params_from_url

    meta = meta or {}
    method = str(meta.get("method") or "GET").upper() or "GET"
    params = normalize_params(meta.get("params") or [])
    seen = {item["name"] for item in params}
    for item in params_from_url(url):
        if item["name"] not in seen:
            params.append(item)
            seen.add(item["name"])
    return method, params


def run_authz_diff(
    urls: list[str],
    *,
    higher_priv: str,
    lower_priv: str,
    target: str,
    allow_external: bool,
    owner_cookie: str | None = None,
    peer_cookie: str | None = None,
    higher_header: str | None = None,
    lower_header: str | None = None,
    endpoint_meta: dict[str, dict] | None = None,
) -> dict[str, Any]:
    from shroodler.authz_diff import run as authz_run

    if higher_header is None or lower_header is None:
        cfg = AgentConfig(
            program="",
            target=target,
            higher_priv_jar=higher_priv or None,
            lower_priv_jar=lower_priv or None,
            owner_cookie=owner_cookie,
            peer_cookie=peer_cookie,
        )
        if higher_header is None:
            higher_header = _auth_header_for_diff(cfg, "higher")
        if lower_header is None:
            lower_header = _auth_header_for_diff(cfg, "lower")
    pages: list[dict[str, Any]] = []
    for u in urls:
        meta = (endpoint_meta or {}).get(u) or {}
        pages.append(
            {
                "url": u,
                "method": str(meta.get("method") or "GET").upper() or "GET",
                "params": list(meta.get("params") or []),
            }
        )
    higher_doc = {"target": target, "pages": pages}
    return authz_run(
        higher_doc,
        cookie_header=lower_header or "",
        allow_external=allow_external,
        higher_cookie_header=higher_header or None,
    )


def _playbook_from_object_ids(
    state: ProgramState,
    object_ids: list[str],
    target: str,
) -> dict[str, Any]:
    from shroodler.peer_write import load_playbook

    writes: list[dict[str, Any]] = []
    idset = set(object_ids)
    for sess in state.sessions:
        path = sess.get("path")
        if not path or not Path(str(path)).is_file():
            continue
        loaded = load_playbook({}, sessions_path=str(path), target=target)
        for write in loaded.get("writes") or []:
            if str(write.get("id_value") or "") in idset:
                writes.append(write)
    seen_keys: set[tuple[str, str, str]] = {
        (str(w.get("method") or ""), str(w.get("url") or ""), str(w.get("id_value") or ""))
        for w in writes
    }
    for oid in object_ids:
        for url in _owning_endpoints(state, oid):
            if not _in_target_origin(url, target):
                continue
            key = ("GET", url, oid)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            writes.append({"method": "GET", "url": url, "id_value": oid, "body": ""})
    return {"target": target, "writes": writes}


def run_peer_write(
    object_ids: list[str],
    *,
    owner_cookie: str,
    peer_cookie: str,
    state: ProgramState,
    target: str,
    allow_external: bool,
) -> dict[str, Any]:
    from shroodler.peer_write import run as peer_run

    playbook = _playbook_from_object_ids(state, object_ids, target)
    return peer_run(
        playbook,
        owner_cookie=owner_cookie,
        peer_cookie=peer_cookie,
        allow_external=allow_external,
        allow_unconfirmed=True,
    )


def _has_unresolved_placeholder(url: str) -> bool:
    return bool(_PLACEHOLDER_RE.search(url or ""))


def run_write_authz(
    endpoints: list[dict],
    *,
    higher_header: str,
    lower_header: str,
    target: str,
    allow_external: bool,
    client: Any | None = None,
) -> dict[str, Any]:
    """Replay write probes as both principals. Lower-priv 2xx is a finding."""
    import httpx

    from shroodler.authz_diff import headers_from_auth_line
    from shroodler.urls import is_loopback_or_local

    if not allow_external and not is_loopback_or_local(target):
        raise ValueError(
            "write-authz refuses non-local targets without --allow-external "
            "(only scan hosts you are authorized to test)"
        )
    http = client or httpx.Client(timeout=8.0, follow_redirects=False)
    own = client is None
    findings: list[dict[str, Any]] = []
    skipped: list[str] = []
    probes: list[dict[str, Any]] = []
    higher_headers = headers_from_auth_line(higher_header)
    lower_headers = headers_from_auth_line(lower_header)
    try:
        for probe in endpoints:
            method = str(probe.get("method") or "").upper() or "POST"
            url = str(probe.get("url") or "")
            if not url:
                skipped.append("missing url")
                continue
            if _has_unresolved_placeholder(url):
                skipped.append(url)
                probes.append(
                    {
                        "method": method,
                        "url": url,
                        "skipped": "unresolved placeholder",
                    }
                )
                continue
            if not allow_external and not is_loopback_or_local(url):
                skipped.append(url)
                probes.append({"method": method, "url": url, "skipped": "out of scope"})
                continue
            body = probe.get("body")
            kwargs: dict[str, Any] = {}
            extra: dict[str, str] = {}
            if isinstance(body, (dict, list)):
                kwargs["json"] = body
            elif body is not None and body != "":
                extra["Content-Type"] = "application/json"
                kwargs["content"] = (
                    body if isinstance(body, (bytes, bytearray)) else str(body).encode("utf-8")
                )
            try:
                higher_resp = http.request(
                    method, url, headers={**extra, **higher_headers}, **kwargs
                )
                higher_status = int(higher_resp.status_code)
            except Exception:  # noqa: BLE001 - per-probe, continue
                higher_status = 0
            try:
                lower_resp = http.request(
                    method, url, headers={**extra, **lower_headers}, **kwargs
                )
                lower_status = int(lower_resp.status_code)
            except Exception:  # noqa: BLE001 - per-probe, continue
                lower_status = 0
            probes.append(
                {
                    "method": method,
                    "url": url,
                    "higher_status": higher_status,
                    "lower_status": lower_status,
                }
            )
            if not (200 <= lower_status < 300):
                continue
            findings.append(
                Finding(
                    id="write-authz-unrestricted",
                    severity="high",
                    category="auth",
                    url=url,
                    description=(
                        f"{method} {url} succeeded for the lower-privilege session "
                        f"(status {lower_status}); this mutation should be denied "
                        f"(higher-priv status {higher_status or 'n/a'})."
                    ),
                    evidence=f"higher={higher_status} lower={lower_status} method={method}",
                    confidence="confirmed",
                ).model_dump(exclude_none=True)
            )
    finally:
        if own:
            http.close()
    return {
        "target": target,
        "findings": findings,
        "probes": probes,
        "skipped": skipped,
    }


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


def _dedupe_js_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str]] = set()
    out: list[Finding] = []
    for item in findings:
        key = (item.id, item.url, (item.evidence or "")[:80])
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _execute_js_analysis(
    action: JSAnalysisAction,
    state: ProgramState,
    config: AgentConfig,
    pacer: Pacer,
) -> dict[str, Any]:
    from shroodler.js_analyzer import JSAnalyzer
    from shroodler.probes.common import body_text, request
    from shroodler.urls import is_loopback_or_local

    config._js_analysis_done = True
    urls = list(action.urls or _js_urls_for_analysis(state))
    if urls and not getattr(state, "js_urls", None):
        state.js_urls = list(urls)
    analyzer = JSAnalyzer()
    findings: list[Finding] = []
    errors: list[str] = []
    analyzed = 0
    allow_external = _allow_external(config.target)
    owner = _owner_for_probes(state, config)
    _session_cm = _bind_probe_session(state, config, pacer)
    _session_cm.__enter__()
    try:
        for url in urls:
            if not url.startswith(("http://", "https://")):
                continue
            if not allow_external and not is_loopback_or_local(url):
                continue
            if not _url_in_program_scope(url, state, config):
                continue
            try:
                resp = request("GET", url, cookie_header=owner, pacer=pacer)
            except Exception as exc:  # noqa: BLE001 - fail closed per URL
                errors.append(f"{url}: {type(exc).__name__}: {exc}")
                continue
            if resp is None:
                errors.append(f"{url}: fetch failed")
                continue
            body = body_text(resp)
            if not body:
                continue
            analyzed += 1
            try:
                findings.extend(analyzer.analyze(body, url, state))
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{url} analyze: {type(exc).__name__}: {exc}")
    finally:
        _session_cm.__exit__(None, None, None)

    findings = _dedupe_js_findings(findings)
    api_n = sum(1 for f in findings if f.id == "js-api-endpoint-found")
    secret_n = sum(1 for f in findings if f.id == "js-hardcoded-secret")
    findings.append(
        Finding(
            id="js-analysis-complete",
            severity="info",
            category="scan-note",
            url=str(config.target or ""),
            description="Finished JavaScript bundle analysis.",
            evidence=(
                f"analyzed {analyzed} js files; found {api_n} api endpoints, "
                f"{secret_n} secrets"
            ),
            confidence="confirmed",
        )
    )
    added = _merge_findings(state, findings)
    out: dict[str, Any] = {
        "pages_crawled": 0,
        "findings_added": added,
        "urls_tested": analyzed,
        "js_files": analyzed,
        "api_endpoints": api_n,
        "secrets": secret_n,
    }
    if errors:
        out["errors"] = errors
    return out


def _stamp_last_seen(state: ProgramState, url: str) -> None:
    """Stamp last_seen=now on an endpoint so it exits the coverage-gap queue."""
    now_str = _now().isoformat()
    meta = state.endpoints.get(url)
    if meta is None:
        state.endpoints[url] = program._endpoint_meta(url, now_str)
        state.endpoints[url]["method"] = "GET"
        state.endpoints[url]["params"] = []
    elif not meta.get("last_seen"):
        meta["last_seen"] = now_str
        if not meta.get("first_seen"):
            meta["first_seen"] = now_str


def _execute_crawl(
    action: CrawlAction,
    state: ProgramState,
    config: AgentConfig,
    pacer: Pacer,
) -> dict[str, Any]:
    from shroodler.crawler import crawl_url

    pages_crawled = 0
    findings_added = 0
    new_endpoints = 0
    errors: list[str] = []
    allow_external = _allow_external(config.target)
    from shroodler.webgoat import is_webgoat_url

    webgoat = is_webgoat_url(config.target) or any(
        is_webgoat_url(u) for u in action.urls
    )
    mode = "headless" if webgoat else "static"
    for url in action.urls:
        if not _in_target_origin(url, config.target):
            continue
        pacer.wait()
        try:
            result = crawl_url(
                url,
                depth=1,
                max_pages=config.max_pages_per_crawl,
                login_recipe=config.login_recipe,
                allow_external=allow_external,
                ignore_robots=config.ignore_robots,
                mode=mode,
            )
        except Exception as exc:  # noqa: BLE001 - per-URL, loop must continue
            errors.append(f"{url}: {type(exc).__name__}: {exc}")
            # Still stamp last_seen so this URL doesn't loop forever as a gap.
            _stamp_last_seen(state, url)
            continue
        doc = result.to_dict() if hasattr(result, "to_dict") else dict(result)
        delta = program.merge_crawl_doc(state, doc)
        # Ensure the attempted URL is stamped even when the crawler returned no
        # pages (e.g. a JSON API endpoint the HTML crawler can't traverse).
        _stamp_last_seen(state, url)
        pages_crawled += int(delta.get("pages") or 0) or len(doc.get("pages") or [])
        findings_added += int(delta.get("new_findings") or 0)
        new_endpoints += int(delta.get("new_endpoints") or 0)
    config._crawled_this_run = True
    out: dict[str, Any] = {
        "pages_crawled": pages_crawled,
        "findings_added": findings_added,
        "new_endpoints": new_endpoints,
    }
    if errors:
        out["errors"] = errors
    return out


def _execute_diff(
    action: DiffAction,
    state: ProgramState,
    config: AgentConfig,
    pacer: Pacer,
) -> dict[str, Any]:
    from shroodler.engagement_history import diff_endpoints, surface_changes

    old = getattr(config, "_prev_endpoints", None)
    if old is None:
        old = state.previous_endpoints or {}
    diff = diff_endpoints(old, state.endpoints)
    findings_added = _merge_findings(state, surface_changes(diff))
    config._diff_done = True
    return {
        "pages_crawled": 0,
        "findings_added": findings_added,
        "urls_tested": 0,
        "added": len(diff.added),
        "removed": len(diff.removed),
        "param_changed": len(diff.param_changed),
    }


def _financial_urls(state: ProgramState, config: AgentConfig) -> list[str]:
    cap = max(0, int(config.max_pages_per_crawl))
    tokens = (
        "amount",
        "price",
        "transfer",
        "payment",
        "order",
        "trade",
        "checkout",
        "wallet",
        "balance",
        "currency",
    )
    out: list[str] = []
    fallback: list[str] = []
    for url, meta in state.endpoints.items():
        if not _in_target_origin(url, config.target):
            continue
        meta = meta or {}
        names = []
        for item in meta.get("params") or []:
            if isinstance(item, dict):
                names.append(str(item.get("name") or ""))
            else:
                names.append(str(item))
        blob = f"{url.lower()} {' '.join(names).lower()}"
        method = str(meta.get("method") or "GET").upper()
        if any(token in blob for token in tokens):
            out.append(url)
        elif method in {"POST", "PUT", "PATCH"}:
            fallback.append(url)
        if len(out) >= cap:
            break
    if out:
        return out[:cap]
    return fallback[:cap]


def _execute_business_logic(
    action: BusinessLogicAction,
    state: ProgramState,
    config: AgentConfig,
    pacer: Pacer,
) -> dict[str, Any]:
    from shroodler.business_logic import (
        financial_probes_for,
        infer_app_domain,
        run_business_probe,
    )

    config._business_logic_done = True
    from shroodler.llm_provider import llm_api_key_env

    env_name = llm_api_key_env(getattr(config, "llm_provider", "anthropic"))
    if not os.environ.get(env_name):
        return {
            "pages_crawled": 0,
            "findings_added": 0,
            "urls_tested": 0,
            "errors": [f"--llm-business-logic requires {env_name}"],
        }
    findings: list[Any] = []
    errors: list[str] = []
    urls_tested = 0
    try:
        model = infer_app_domain(state.js_bundles, state.api_samples, config=config)
        if model.financial:
            owner = _owner_for_probes(state, config)
            _session_cm = _bind_probe_session(state, config, pacer)
            _session_cm.__enter__()
            try:
                for url in _financial_urls(state, config):
                    for probe in financial_probes_for(url):
                        try:
                            findings.extend(
                                run_business_probe(
                                    probe, cookie_header=owner, pacer=pacer
                                )
                            )
                            urls_tested += 1
                        except Exception as exc:  # noqa: BLE001
                            errors.append(f"{url} {probe.id}: {type(exc).__name__}: {exc}")
            finally:
                _session_cm.__exit__(None, None, None)
    except Exception as exc:  # noqa: BLE001 - fail closed
        errors.append(f"business-logic: {type(exc).__name__}: {exc}")
    findings_added = _merge_findings(state, findings)
    out: dict[str, Any] = {
        "pages_crawled": 0,
        "findings_added": findings_added,
        "urls_tested": urls_tested,
    }
    if errors:
        out["errors"] = errors
    return out


def _execute_chain(
    action: ChainAction,
    state: ProgramState,
    config: AgentConfig,
    pacer: Pacer,
) -> dict[str, Any]:
    from shroodler.attack_chain import bind_builtin_chains, load_chain_spec, run_chain

    config._chain_done = True
    findings: list[Any] = []
    errors: list[str] = []
    urls_tested = 0
    chains = []
    if config.run_probes:
        chains.extend(bind_builtin_chains(state, config))
    for spec in config.chain_specs or []:
        try:
            chains.append(load_chain_spec(spec))
        except Exception as exc:  # noqa: BLE001 - fail closed per spec
            errors.append(f"chain-spec {spec}: {type(exc).__name__}: {exc}")
    for chain in chains:
        try:
            raw = run_chain(chain, config=config, pacer=pacer)
            findings.extend(raw.get("findings") or [])
            urls_tested += int(raw.get("urls_tested") or 0)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"chain {chain.name}: {type(exc).__name__}: {exc}")
    findings_added = _merge_findings(state, findings)
    out: dict[str, Any] = {
        "pages_crawled": 0,
        "findings_added": findings_added,
        "urls_tested": urls_tested,
    }
    if errors:
        out["errors"] = errors
    return out


def _execute_authz(
    action: AuthzDiffAction,
    state: ProgramState,
    config: AgentConfig,
    pacer: Pacer,
) -> dict[str, Any]:
    pacer.wait()
    raw = run_authz_diff(
        action.urls,
        higher_priv=str(config.higher_priv_jar or ""),
        lower_priv=str(config.lower_priv_jar or ""),
        target=config.target,
        allow_external=_allow_external(config.target),
        owner_cookie=config.owner_cookie,
        peer_cookie=config.peer_cookie,
        endpoint_meta={u: (state.endpoints.get(u) or {}) for u in action.urls},
    )
    findings_added = _merge_findings(state, list(raw.get("findings") or []))
    program.mark_tested(state, action.urls, "tested_authz")
    return {
        "pages_crawled": 0,
        "findings_added": findings_added,
        "urls_tested": len(action.urls),
    }


def _execute_peer_write(
    action: PeerWriteAction,
    state: ProgramState,
    config: AgentConfig,
    pacer: Pacer,
) -> dict[str, Any]:
    pacer.wait()
    raw = run_peer_write(
        action.object_ids,
        owner_cookie=str(config.owner_cookie),
        peer_cookie=str(config.peer_cookie),
        state=state,
        target=config.target,
        allow_external=_allow_external(config.target),
    )
    findings_added = _merge_findings(state, list(raw.get("findings") or []))
    urls: list[str] = []
    for oid in action.object_ids:
        urls.extend(_owning_endpoints(state, oid))
    program.mark_tested(state, urls, "tested_peer_write")
    return {
        "pages_crawled": 0,
        "findings_added": findings_added,
        "object_ids": list(action.object_ids),
        "urls_tested": len(urls),
    }


def _execute_write_authz(
    action: WriteAuthzAction,
    state: ProgramState,
    config: AgentConfig,
    pacer: Pacer,
) -> dict[str, Any]:
    pacer.wait()
    raw = run_write_authz(
        action.endpoints,
        higher_header=_auth_header_for_diff(config, "higher"),
        lower_header=_auth_header_for_diff(config, "lower"),
        target=config.target,
        allow_external=_allow_external(config.target),
    )
    findings_added = _merge_findings(state, list(raw.get("findings") or []))
    config._write_authz_done = True
    out: dict[str, Any] = {
        "pages_crawled": 0,
        "findings_added": findings_added,
        "urls_tested": sum(
            1 for p in (raw.get("probes") or []) if "lower_status" in p
        ),
        "probes": list(raw.get("probes") or []),
    }
    if raw.get("skipped"):
        out["skipped"] = list(raw["skipped"])
    return out


def _execute_auto_register(
    action: AutoRegisterAction,
    state: ProgramState,
    config: AgentConfig,
    pacer: Pacer,
) -> dict[str, Any]:
    from shroodler.second_account import auto_register_peer

    config._auto_register_done = True
    findings: list[Any] = []
    errors: list[str] = []
    try:
        findings = auto_register_peer(state, config, pacer=pacer)
    except Exception as exc:  # noqa: BLE001 - fail closed
        errors.append(f"auto-register: {type(exc).__name__}: {exc}")
    _sync_peer_session_from_config(state, config)
    findings_added = _merge_findings(state, findings)
    out: dict[str, Any] = {
        "pages_crawled": 0,
        "findings_added": findings_added,
        "urls_tested": 1 if findings else 0,
    }
    if errors:
        out["errors"] = errors
    return out


def _execute_login(
    action: LoginAction,
    state: ProgramState,
    config: AgentConfig,
    pacer: Pacer,
) -> dict[str, Any]:
    from shroodler.login_executor import LoginExecutor, apply_peer_session, apply_session

    config._login_done = True
    recipe_path = str(config.login_recipe or "")
    errors: list[str] = []
    result = None
    try:
        executor = LoginExecutor(pacer=pacer)
        result = asyncio.run(executor.run(recipe_path, seed=config.target))
    except Exception as exc:  # noqa: BLE001
        errors.append(f"login-recipe: {type(exc).__name__}: {exc}")

    url = str(config.target or "")
    if result is not None and result.success:
        apply_session(state, result.inject_headers, result.inject_cookies)
        _apply_login_to_config(config, result)
        token = result.extracted.get("access_token") or result.extracted.get("token") or ""
        if token:
            state.bearer_token = token
        elif result.inject_headers.get("Authorization"):
            state.bearer_token = (
                result.inject_headers["Authorization"].split(None, 1)[-1].strip()
            )
        if int(getattr(config, "reauth_max_retries", 0) or 0) > 0:
            state.reauth_callback = _make_reauth_callback(state, config, pacer)
        peer_path = str(getattr(config, "peer_recipe", None) or "").strip()
        if peer_path:
            peer_result = None
            try:
                peer_executor = LoginExecutor(pacer=pacer)
                peer_result = asyncio.run(
                    peer_executor.run(peer_path, seed=config.target)
                )
            except Exception as exc:  # noqa: BLE001
                errors.append(f"peer-recipe: {type(exc).__name__}: {exc}")
            if peer_result is not None and peer_result.success:
                apply_peer_session(
                    state, peer_result.inject_headers, peer_result.inject_cookies
                )
                _apply_peer_to_config(config, peer_result)
        finding = Finding(
            id="login-recipe-success",
            severity="info",
            category="scan-note",
            url=url,
            description="Login recipe succeeded; session cookies/headers stored for probes.",
            evidence=(
                f"headers={len(result.inject_headers)} "
                f"cookies={len(result.inject_cookies)} "
                f"extracted={','.join(result.extracted) or '-'}"
            ),
            confidence="confirmed",
        )
        added = _merge_findings(state, [finding])
        out: dict[str, Any] = {
            "pages_crawled": 0,
            "findings_added": added,
            "urls_tested": 1,
            "login": True,
        }
        if errors:
            out["errors"] = errors
        return out

    state.login_failed = True
    err = ""
    if result is not None:
        err = result.error or "login failed"
    elif errors:
        err = errors[0]
    finding = Finding(
        id="login-recipe-failed",
        severity="medium",
        category="scan-note",
        url=url,
        description="Login recipe failed; probes will continue without that session.",
        evidence=err or "login failed",
        confidence="confirmed",
    )
    added = _merge_findings(state, [finding])
    out: dict[str, Any] = {
        "pages_crawled": 0,
        "findings_added": added,
        "urls_tested": 1,
        "login": False,
    }
    if errors:
        out["errors"] = errors
    elif err:
        out["errors"] = [err]
    return out


def _execute_probe(
    action: ProbeAction,
    state: ProgramState,
    config: AgentConfig,
    pacer: Pacer,
) -> dict[str, Any]:
    owner = _owner_for_probes(state, config)
    peer = _probe_auth_headers(config)[1]
    auth_header = _owner_auth_line(state, config)
    if not auth_header and owner.lower().startswith("authorization:"):
        auth_header = owner
    cookie_header = _merged_owner_cookie(state, config)
    if not cookie_header:
        cookie_header = "" if auth_header else owner
    _session_cm = _bind_probe_session(state, config, pacer)
    _session_cm.__enter__()
    try:
        return _finish_probe_action(
            action,
            state,
            config,
            pacer,
            owner,
            peer,
            auth_header,
            cookie_header,
        )
    finally:
        _session_cm.__exit__(None, None, None)


def _finish_probe_action(
    action: ProbeAction,
    state: ProgramState,
    config: AgentConfig,
    pacer: Pacer,
    owner: str,
    peer: str,
    auth_header: str,
    cookie_header: str,
) -> dict[str, Any]:
    from shroodler.probes.crlf import probe_crlf
    from shroodler.probes.dom_xss import probe_dom_xss
    from shroodler.probes.graphql import probe_graphql
    from shroodler.probes.host_header import hostname_of, probe_host_header
    from shroodler.probes.idor import probe_idor
    from shroodler.probes.jwt import probe_jwt
    from shroodler.probes.mass_assignment import probe_mass_assignment
    from shroodler.probes.open_redirect import probe_open_redirect
    from shroodler.probes.path_traversal import probe_path_traversal
    from shroodler.probes.prototype_pollution import probe_prototype_pollution
    from shroodler.probes.rate_limit import probe_rate_limit
    from shroodler.probes.smuggling import hostname_of as smuggle_host
    from shroodler.probes.smuggling import probe_smuggling
    from shroodler.probes.sqli import probe_sqli
    from shroodler.probes.ssrf import probe_ssrf
    from shroodler.probes.ssti import probe_ssti
    from shroodler.probes.websocket import probe_websocket
    from shroodler.probes.xss import probe_xss
    from shroodler.probes.xxe import probe_xxe

    findings: list[Any] = []
    errors: list[str] = []
    seen_hosts: set[str] = set()
    seen_graphql: set[str] = set()
    seen_smuggle: set[str] = set()
    seen_rl: set[str] = set()

    def _run(label: str, fn) -> None:
        try:
            findings.extend(fn())
        except Exception as exc:  # noqa: BLE001 - per-probe, loop must continue
            errors.append(f"{url} {label}: {type(exc).__name__}: {exc}")

    for url in action.urls:
        if not _in_target_origin(url, config.target):
            continue
        if not _url_in_program_scope(url, state, config):
            continue
        meta = state.endpoints.get(url) or {}
        method, params = _probe_params(url, meta)
        view_url = str(meta.get("view_url") or "")
        if config.probe_sqli and method in {"GET", "POST"} and params:
            _run("sqli", lambda: probe_sqli(url, method, params, owner, pacer=pacer))
        if config.probe_xss and method in {"GET", "POST"} and params:
            _run(
                "xss",
                lambda: probe_xss(
                    url, method, params, owner, view_url=view_url, pacer=pacer
                ),
            )
        if config.probe_path_traversal:
            _run(
                "path-traversal",
                lambda: probe_path_traversal(url, params, owner, pacer=pacer),
            )
        if config.probe_jwt and (cookie_header or auth_header):
            _run(
                "jwt",
                lambda: probe_jwt(url, cookie_header, auth_header, pacer=pacer),
            )
        if config.probe_idor and peer:
            _run("idor", lambda: probe_idor(url, owner, peer, pacer=pacer))
        if config.run_ssrf and method in {"GET", "POST"} and params:
            _run("ssrf", lambda: probe_ssrf(url, method, params, owner, pacer=pacer))
        if config.run_open_redirect and method in {"GET", "POST"} and params:
            _run(
                "open-redirect",
                lambda: probe_open_redirect(url, method, params, owner, pacer=pacer),
            )
        if config.run_host_header:
            host = hostname_of(url)
            if host and host not in seen_hosts:
                seen_hosts.add(host)
                _run("host-header", lambda: probe_host_header(url, owner, pacer=pacer))
        if config.run_ssti and method in {"GET", "POST"} and params:
            _run("ssti", lambda: probe_ssti(url, method, params, owner, pacer=pacer))
        if config.run_xxe and method in {"GET", "POST"}:
            content_type = str(meta.get("content_type") or meta.get("content-type") or "")
            _run(
                "xxe",
                lambda: probe_xxe(
                    url,
                    method,
                    params,
                    owner,
                    pacer=pacer,
                    content_type=content_type,
                ),
            )
        if config.run_graphql:
            origin = origin_of(url)
            if origin and origin not in seen_graphql:
                seen_graphql.add(origin)
                _run("graphql", lambda: probe_graphql(url, owner, pacer=pacer))
        if config.run_crlf and method in {"GET", "POST", "PUT", "PATCH"}:
            _run("crlf", lambda: probe_crlf(url, method, params, owner, pacer=pacer))
        if config.run_prototype_pollution:
            content_type = str(meta.get("content_type") or meta.get("content-type") or "")
            _run(
                "prototype-pollution",
                lambda: probe_prototype_pollution(
                    url,
                    method,
                    params,
                    owner,
                    pacer=pacer,
                    content_type=content_type,
                ),
            )
        if config.run_dom_xss and method in {"GET", "POST"} and params:
            _run(
                "dom-xss",
                lambda: probe_dom_xss(url, method, params, owner, pacer=pacer),
            )
        if config.run_rate_limit and url not in seen_rl:
            seen_rl.add(url)
            _run(
                "rate-limit",
                lambda: probe_rate_limit(url, method, owner, pacer=pacer),
            )
        if config.run_mass_assignment and method in {"POST", "PUT", "PATCH"}:
            content_type = str(meta.get("content_type") or meta.get("content-type") or "")
            _run(
                "mass-assignment",
                lambda: probe_mass_assignment(
                    url, method, owner, pacer=pacer, content_type=content_type
                ),
            )
        if config.run_smuggling:
            host = smuggle_host(url)
            if host and host not in seen_smuggle:
                seen_smuggle.add(host)
                _run(
                    "smuggling",
                    lambda: probe_smuggling(
                        url,
                        owner,
                        allow_external=bool(config.allow_external),
                        pacer=pacer,
                    ),
                )
        if config.run_websocket:
            js_bits: list[str] = []
            for bundle in (getattr(state, "js_bundles", None) or [])[:8]:
                if isinstance(bundle, str):
                    js_bits.append(bundle)
                elif isinstance(bundle, dict):
                    js_bits.append(
                        str(bundle.get("source") or bundle.get("content") or "")
                    )

            def _ws_probe(u=url, src="\n".join(js_bits)):
                hits, found = probe_websocket(
                    u,
                    owner,
                    pacer=pacer,
                    js_source=src,
                    base_url=config.target,
                )
                existing = list(getattr(state, "websocket_endpoints", None) or [])
                for item in found:
                    if item not in existing:
                        existing.append(item)
                state.websocket_endpoints = existing
                return hits

            _run("websocket", _ws_probe)
    findings_added = _merge_findings(state, findings)
    program.mark_tested(state, action.urls, "tested_payload")
    out: dict[str, Any] = {
        "pages_crawled": 0,
        "findings_added": findings_added,
        "urls_tested": len(action.urls),
    }
    if errors:
        out["errors"] = errors
    return out


def _openapi_auth_header(state: ProgramState, config: AgentConfig) -> tuple[str, str]:
    owner = _owner_for_probes(state, config)
    peer = _probe_auth_headers(config)[1]
    token = (state.bearer_token or "").strip()
    if token and not owner.lower().startswith("authorization:"):
        extra = getattr(state, "login_headers", None) or {}
        if not extra.get("Authorization"):
            owner = f"Authorization: Bearer {token}"
    return owner, peer


def _execute_openapi_discover(
    action: OpenApiDiscoverAction,
    state: ProgramState,
    config: AgentConfig,
    pacer: Pacer,
) -> dict[str, Any]:
    from shroodler.openapi import discover_specs, merge_openapi_into_state, parse_spec

    config._openapi_discover_done = True
    cookie, _peer = _openapi_auth_header(state, config)
    errors: list[str] = []
    new_endpoints = 0
    spec_urls: list[str] = []
    _session_cm = _bind_probe_session(state, config, pacer)
    _session_cm.__enter__()
    try:
        found = discover_specs(
            config.target,
            cookie_header=cookie,
            pacer=pacer,
        )
    except Exception as exc:  # noqa: BLE001
        errors.append(f"openapi-discover: {type(exc).__name__}: {exc}")
        found = []
    finally:
        _session_cm.__exit__(None, None, None)
    for spec_url, spec in found:
        try:
            endpoints = parse_spec(spec, config.target)
            new_endpoints += merge_openapi_into_state(state, endpoints, spec_url)
            spec_urls.append(spec_url)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{spec_url}: {type(exc).__name__}: {exc}")
    out: dict[str, Any] = {
        "pages_crawled": 0,
        "findings_added": sum(1 for f in state.findings if f.id == "openapi-spec-found"),
        "new_endpoints": new_endpoints,
        "specs": spec_urls,
    }
    if errors:
        out["errors"] = errors
    return out


def _execute_openapi_probe(
    action: OpenApiProbeAction,
    state: ProgramState,
    config: AgentConfig,
    pacer: Pacer,
) -> dict[str, Any]:
    from shroodler.probes.openapi_probe import probe_openapi_endpoints

    owner, peer = _openapi_auth_header(state, config)
    findings: list[Any] = []
    errors: list[str] = []
    tested: list[str] = []
    _session_cm = _bind_probe_session(state, config, pacer)
    _session_cm.__enter__()
    try:
        for row in action.endpoints:
            url = str(row.get("url") or "")
            try:
                findings.extend(
                    probe_openapi_endpoints(
                        [row],
                        cookie_header=owner,
                        peer_cookie=peer,
                        pacer=pacer,
                    )
                )
            except Exception as exc:  # noqa: BLE001 - per-endpoint, loop must continue
                errors.append(f"{url} openapi-probe: {type(exc).__name__}: {exc}")
            if url:
                tested.append(url)
                row["tested_payload"] = True
    finally:
        _session_cm.__exit__(None, None, None)
    findings_added = _merge_findings(state, findings)
    program.mark_tested(state, tested, "tested_payload")
    out: dict[str, Any] = {
        "pages_crawled": 0,
        "findings_added": findings_added,
        "urls_tested": len(tested),
    }
    if errors:
        out["errors"] = errors
    return out


def _execute_tls_check(
    action: TLSCheckAction,
    state: ProgramState,
    config: AgentConfig,
) -> dict[str, Any]:
    from shroodler.tls_check import check_target_tls

    config._tls_check_done = True
    errors: list[str] = []
    findings: list[Any] = []
    try:
        findings = check_target_tls(config.target)
    except Exception as exc:  # noqa: BLE001
        errors.append(f"tls-check: {type(exc).__name__}: {exc}")
    added = _merge_findings(state, findings)
    out: dict[str, Any] = {
        "pages_crawled": 0,
        "findings_added": added,
        "urls_tested": 1,
    }
    if errors:
        out["errors"] = errors
    return out


def _execute_content_discover(
    action: ContentDiscoverAction,
    state: ProgramState,
    config: AgentConfig,
    pacer: Pacer,
) -> dict[str, Any]:
    from shroodler.content_discovery import discover_content

    config._content_discover_done = True
    owner = _owner_for_probes(state, config)
    errors: list[str] = []
    findings: list[Any] = []
    _session_cm = _bind_probe_session(state, config, pacer)
    _session_cm.__enter__()
    try:
        findings = discover_content(config.target, owner, pacer=pacer)
    except Exception as exc:  # noqa: BLE001
        errors.append(f"content-discover: {type(exc).__name__}: {exc}")
    finally:
        _session_cm.__exit__(None, None, None)
    added = _merge_findings(state, findings)
    out: dict[str, Any] = {
        "pages_crawled": 0,
        "findings_added": added,
        "urls_tested": 1,
    }
    if errors:
        out["errors"] = errors
    return out


def _execute_report(state: ProgramState) -> dict[str, Any]:
    from shroodler.dedup import deduplicate
    from shroodler.program import _finding_from_dict, _finding_to_dict

    rebuilt: list[Finding] = []
    for item in deduplicate([_finding_to_dict(f) for f in state.findings]):
        parsed = _finding_from_dict(item)
        if parsed is not None:
            rebuilt.append(parsed)
    state.findings = rebuilt
    confirmed = _confirmed_findings(state)
    return {
        "pages_crawled": 0,
        "findings_added": 0,
        "confirmed": len(confirmed),
        "summary": [
            {
                "id": f.id,
                "url": f.url,
                "severity": f.severity,
                "description": f.description,
            }
            for f in confirmed
        ],
    }


def _execute_idor(
    action: IDORScanAction,
    state: ProgramState,
    config: AgentConfig,
    pacer: Pacer,
) -> dict[str, Any]:
    from shroodler.idor_engine import IDOREngine

    config._idor_scan_done = True
    sessions = _resolve_idor_sessions(state, config)
    findings: list[Any] = []
    errors: list[str] = []
    tested = 0
    if sessions is None:
        added = 0
    else:
        owner_headers, owner_cookies, peer_headers, peer_cookies = sessions
        engine = IDOREngine(
            state,
            config,
            owner_headers,
            owner_cookies,
            peer_headers,
            peer_cookies,
            pacer,
        )
        try:
            findings = engine.run_sync()
        except Exception as exc:  # noqa: BLE001 - fail closed
            errors.append(f"idor-scan: {type(exc).__name__}: {exc}")
            findings = []
        tested = int(getattr(engine, "tested_count", 0) or 0)
        idor_n = sum(1 for f in findings if getattr(f, "id", None) == "idor-cross-account")
        findings.append(
            Finding(
                id="idor-scan-complete",
                severity="info",
                category="scan-note",
                url=str(config.target or ""),
                description="Finished cross-account IDOR comparison.",
                evidence=f"tested {tested} endpoints; found {idor_n} IDOR candidates",
                confidence="confirmed",
            )
        )
        added = _merge_findings(state, findings)
    out: dict[str, Any] = {
        "pages_crawled": 0,
        "findings_added": added,
        "urls_tested": tested,
    }
    if errors:
        out["errors"] = errors
    return out


def execute_action(
    action: AgentAction,
    state: ProgramState,
    config: AgentConfig,
    pacer: Pacer | None = None,
) -> dict[str, Any]:
    clock = pacer or _new_pacer()
    if isinstance(action, LoginAction):
        return _execute_login(action, state, config, clock)
    if isinstance(action, TLSCheckAction):
        return _execute_tls_check(action, state, config)
    if isinstance(action, ContentDiscoverAction):
        return _execute_content_discover(action, state, config, clock)
    if isinstance(action, CrawlAction):
        return _execute_crawl(action, state, config, clock)
    if isinstance(action, JSAnalysisAction):
        return _execute_js_analysis(action, state, config, clock)
    if isinstance(action, DiffAction):
        return _execute_diff(action, state, config, clock)
    if isinstance(action, OpenApiDiscoverAction):
        return _execute_openapi_discover(action, state, config, clock)
    if isinstance(action, AutoRegisterAction):
        return _execute_auto_register(action, state, config, clock)
    if isinstance(action, AuthzDiffAction):
        return _execute_authz(action, state, config, clock)
    if isinstance(action, IDORScanAction):
        return _execute_idor(action, state, config, clock)
    if isinstance(action, WriteAuthzAction):
        return _execute_write_authz(action, state, config, clock)
    if isinstance(action, PeerWriteAction):
        return _execute_peer_write(action, state, config, clock)
    if isinstance(action, ProbeAction):
        return _execute_probe(action, state, config, clock)
    if isinstance(action, OpenApiProbeAction):
        return _execute_openapi_probe(action, state, config, clock)
    if isinstance(action, BusinessLogicAction):
        return _execute_business_logic(action, state, config, clock)
    if isinstance(action, ChainAction):
        return _execute_chain(action, state, config, clock)
    if isinstance(action, ReportAction):
        return _execute_report(state)
    raise TypeError(f"unknown action {type(action)!r}")


def _describe_action(action: AgentAction) -> dict[str, Any]:
    if isinstance(action, LoginAction):
        return {"login": True}
    if isinstance(action, TLSCheckAction):
        return {"tls_check": True}
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
    history.append(
        HistoryEntry(
            iteration=iteration,
            action=str(decision.action),
            params=dict(decision.params or {}),
            reasoning=decision.reasoning,
            findings_added=added,
            summary=result.summary,
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
        from shroodler.llm_provider import llm_api_key_env

        env_name = llm_api_key_env(getattr(config, "llm_provider", "anthropic"))
        if not os.environ.get(env_name):
            return AgentResult(
                iterations=0,
                confirmed=0,
                log=[],
                state_path="",
                errors=[f"--llm-agent requires {env_name}"],
            )
    probe_memory = None
    if config.llm_agent:
        from shroodler.llm_agent.probe_memory import ProbeMemory

        probe_memory = ProbeMemory(_probe_memory_db_path(config))
    try:
        return _run_agent_body(config, probe_memory)
    finally:
        if probe_memory is not None:
            probe_memory.close()


def _run_agent_body(config: AgentConfig, probe_memory: Any = None) -> AgentResult:
    state = program.load(config.program)
    assert_target_in_scope(state, config.target)
    path = str(program.state_path(state.slug))
    log: list[dict[str, Any]] = []
    errors: list[str] = []
    consecutive_errors = 0
    _crawl_stall_count = 0
    pacer = _new_pacer()
    llm_history: list[Any] = []
    config._llm_cost_usd = 0.0
    config._llm_last_guardrail = ""
    if config.write_authz_spec:
        _ensure_write_authz_endpoints(config)

    config._prev_endpoints = copy.deepcopy(state.endpoints)
    config._run_started_at = _now().isoformat()
    config._endpoint_count_at_start = len(state.endpoints)
    config._crawled_this_run = False
    config._diff_done = False
    config._business_logic_done = False
    config._chain_done = False
    config._openapi_discover_done = False
    config._tls_check_done = False
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
                result = execute_action(action, state, config, pacer=pacer)
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

    confirmed = _confirmed_findings(state)
    if not config.dry_run:
        state.previous_endpoints = copy.deepcopy(config._prev_endpoints)
        program.record_run_summary(
            state,
            {
                "started_at": getattr(config, "_run_started_at", None) or _now().isoformat(),
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
