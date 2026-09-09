"""Autonomous engagement loop over per-program state.

Reads ~/.shroodler/programs/<slug>/state.json, picks the next highest-value
action (crawl → diff → openapi-discover → authz-diff → write-authz →
peer-write → probe → openapi-probe → business-logic → chain → report),
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
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from shroodler import program
from shroodler.models import Finding
from shroodler.pacer import Pacer
from shroodler.program import ProgramState, object_ids_flat, url_to_pattern
from shroodler.urls import is_loopback_or_local, same_origin

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
    higher_priv_jar: str | None = None
    lower_priv_jar: str | None = None
    owner_cookie: str | None = None
    peer_cookie: str | None = None
    dry_run: bool = False
    llm_triage: bool = False  # opt-in; requires ANTHROPIC_API_KEY in env
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
    reprobe: bool = False  # reset tested_payload before the loop
    run_diff: bool = False  # opt-in; also auto-runs when a previous run exists
    run_business_logic: bool = False  # --llm-business-logic
    chain_specs: list[str] = field(default_factory=list)
    run_openapi_discovery: bool = True  # on by default; mapping, not probing
    run_openapi_probes: bool = True


@dataclass
class CrawlAction:
    urls: list[str]


@dataclass
class DiffAction:
    pass


@dataclass
class OpenApiDiscoverAction:
    pass


@dataclass
class AuthzDiffAction:
    urls: list[str]


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
    CrawlAction
    | DiffAction
    | OpenApiDiscoverAction
    | AuthzDiffAction
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
        if _has_unresolved_placeholder(url):
            continue
        last_seen = str((meta or {}).get("last_seen") or "")
        ts = _parse_ts(last_seen)
        if ts is None or (now - ts) > _STALE_AFTER:
            stale.append((url, last_seen))
    stale.sort(key=lambda item: item[1] or "")
    urls = [url for url, _ in stale]
    if not state.endpoints and _in_target_origin(config.target, config.target):
        urls = [config.target]
    elif not urls and not any(
        _in_target_origin(u, config.target) for u in state.endpoints
    ):
        if _in_target_origin(config.target, config.target):
            urls = [config.target]
    return urls[:cap]


def _untested_authz_urls(state: ProgramState, config: AgentConfig) -> list[str]:
    cap = max(0, int(config.max_pages_per_crawl))
    ranked: list[tuple[int, int, str]] = []
    for index, (url, meta) in enumerate(state.endpoints.items()):
        if not _in_target_origin(url, config.target):
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


def decide_next_action(
    state: ProgramState,
    config: AgentConfig,
    crawl_stall_count: int = 0,
) -> AgentAction | None:
    """Priority: Crawl > Diff > OpenApiDiscover > AuthzDiff > WriteAuthz >
    PeerWrite > Probe > OpenApiProbe > BusinessLogic > Chain > Report."""
    crawl_urls = crawl_coverage_gaps(state, config)
    if crawl_urls and crawl_stall_count < _CRAWL_STALL_LIMIT:
        return CrawlAction(urls=crawl_urls)

    if _should_run_diff(state, config):
        return DiffAction()

    if (
        config.run_openapi_discovery
        and not getattr(config, "_openapi_discover_done", False)
        and not state.openapi_spec_url
    ):
        return OpenApiDiscoverAction()

    authz_urls: list[str] = []
    object_ids: list[str] = []
    write_endpoints: list[dict] = []
    if config.higher_priv_jar and config.lower_priv_jar:
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
    if write_endpoints:
        return WriteAuthzAction(endpoints=write_endpoints)
    if object_ids:
        return PeerWriteAction(object_ids=object_ids)

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
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return {
            "pages_crawled": 0,
            "findings_added": 0,
            "urls_tested": 0,
            "errors": ["--llm-business-logic requires ANTHROPIC_API_KEY"],
        }
    findings: list[Any] = []
    errors: list[str] = []
    urls_tested = 0
    try:
        model = infer_app_domain(state.js_bundles, state.api_samples)
        if model.financial:
            owner, _peer = _probe_auth_headers(config)
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


def _execute_probe(
    action: ProbeAction,
    state: ProgramState,
    config: AgentConfig,
    pacer: Pacer,
) -> dict[str, Any]:
    from shroodler.probes.idor import probe_idor
    from shroodler.probes.jwt import probe_jwt
    from shroodler.probes.path_traversal import probe_path_traversal
    from shroodler.probes.sqli import probe_sqli
    from shroodler.probes.xss import probe_xss

    owner, peer = _probe_auth_headers(config)
    auth_header = owner if owner.lower().startswith("authorization:") else ""
    cookie_header = "" if auth_header else owner
    findings: list[Any] = []
    errors: list[str] = []

    def _run(label: str, fn) -> None:
        try:
            findings.extend(fn())
        except Exception as exc:  # noqa: BLE001 - per-probe, loop must continue
            errors.append(f"{url} {label}: {type(exc).__name__}: {exc}")

    for url in action.urls:
        if not _in_target_origin(url, config.target):
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
    owner, peer = _probe_auth_headers(config)
    token = (state.bearer_token or "").strip()
    if token and not owner.lower().startswith("authorization:"):
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
    try:
        found = discover_specs(
            config.target,
            cookie_header=cookie,
            pacer=pacer,
        )
    except Exception as exc:  # noqa: BLE001
        errors.append(f"openapi-discover: {type(exc).__name__}: {exc}")
        found = []
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


def _execute_report(state: ProgramState) -> dict[str, Any]:
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


def execute_action(
    action: AgentAction,
    state: ProgramState,
    config: AgentConfig,
    pacer: Pacer | None = None,
) -> dict[str, Any]:
    clock = pacer or _new_pacer()
    if isinstance(action, CrawlAction):
        return _execute_crawl(action, state, config, clock)
    if isinstance(action, DiffAction):
        return _execute_diff(action, state, config, clock)
    if isinstance(action, OpenApiDiscoverAction):
        return _execute_openapi_discover(action, state, config, clock)
    if isinstance(action, AuthzDiffAction):
        return _execute_authz(action, state, config, clock)
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
    if isinstance(action, CrawlAction):
        return {"urls": list(action.urls)}
    if isinstance(action, DiffAction):
        return {"diff": True}
    if isinstance(action, OpenApiDiscoverAction):
        return {"openapi_discover": True}
    if isinstance(action, AuthzDiffAction):
        return {"urls": list(action.urls)}
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


def run_agent(config: AgentConfig) -> AgentResult:
    state = program.load(config.program)
    assert_target_in_scope(state, config.target)
    path = str(program.state_path(state.slug))
    log: list[dict[str, Any]] = []
    errors: list[str] = []
    consecutive_errors = 0
    _crawl_stall_count = 0
    pacer = _new_pacer()
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
