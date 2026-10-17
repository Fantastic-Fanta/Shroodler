"""Action executors for the agent loop.

The run_* and _execute_* functions plus the execute_action dispatcher, split
out of agent.py. Shared low-level helpers and the decision layer stay in
agent.py and are imported here.
"""

from __future__ import annotations

import asyncio
import os
import threading
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from shroodler import program
from shroodler.agent import (
    _AGG_TIMEOUT,
    _AGG_WORKERS,
    _PROBE_WORKERS,
    _allow_external,
    _apply_login_to_config,
    _apply_peer_to_config,
    _auth_header_for_diff,
    _bind_probe_session,
    _confirmed_findings,
    _has_unresolved_placeholder,
    _in_target_origin,
    _js_urls_for_analysis,
    _make_reauth_callback,
    _merge_findings,
    _merged_owner_cookie,
    _new_pacer,
    _owner_auth_line,
    _owner_for_probes,
    _owning_endpoints,
    _probe_auth_headers,
    _resolve_idor_sessions,
    _sync_peer_session_from_config,
    _url_in_program_scope,
    emit_log_entry,
)
from shroodler.agent_types import (
    AgentAction,
    AgentConfig,
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
from shroodler.program import ProgramState
from shroodler.urls import is_loopback_or_local
from shroodler.urls import origin as origin_of
from shroodler.util import now_utc


def _probe_params(url: str, meta: dict | None) -> tuple[str, list[dict]]:
    from shroodler.probes.common import normalize_params, params_from_url

    meta = meta or {}
    method = str(meta.get("method") or "GET").upper() or "GET"
    params = normalize_params(meta.get("params") or [], url=url)
    seen = {item["name"] for item in params}
    for item in params_from_url(url):
        if item["name"] not in seen:
            params.append(item)
            seen.add(item["name"])
    # When the endpoint declares a JSON request body, mark body params in="json"
    # so inject() sends a JSON body instead of urlencoded form data. Gated on
    # explicit content-type evidence so genuine form endpoints are untouched.
    # normalize_params defaults `in` to "query", so on a body method a param is
    # a body field unless it actually appears in the URL query string.
    content_type = str(meta.get("content_type") or meta.get("content-type") or "").lower()
    if method in {"POST", "PUT", "PATCH"} and "json" in content_type:
        from urllib.parse import parse_qsl, urlparse

        query_names = {k for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)}
        for item in params:
            where = str(item.get("in") or "").lower()
            if item["name"] in query_names or where == "path":
                continue
            if where in {"", "query", "body", "form"}:
                item["in"] = "json"
    return method, params



def _looks_like_search_probe(url: str, params: list[dict]) -> bool:
    """True when the path looks like search or a param is named q."""

    parsed = urlparse(url or "")
    path = (parsed.path or "").lower()
    fragment = (parsed.fragment or "").lower()
    if "/search" in path or "/search" in fragment:
        return True
    for item in params or []:
        if str(item.get("name") or "").lower() == "q":
            return True
    return False



def _ensure_q_param(params: list[dict]) -> list[dict]:
    out = [dict(item) for item in (params or [])]
    if not any(str(item.get("name") or "").lower() == "q" for item in out):
        out.append({"name": "q", "in": "query"})
    return out



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
    now_str = now_utc().isoformat()
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
                storage_state=(config.higher_priv_jar or "").strip() or None,
                allow_external=allow_external,
                ignore_robots=config.ignore_robots,
                harvest_robots=config.harvest_robots,
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
    from shroodler.llm_provider import llm_api_key_env, provider_requires_api_key

    provider = getattr(config, "llm_provider", "anthropic")
    env_name = llm_api_key_env(provider)
    if provider_requires_api_key(provider) and not os.environ.get(env_name):
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
    mutate = bool(getattr(config, "workflow_mutate", False))
    for chain in chains:
        try:
            raw = run_chain(chain, config=config, pacer=pacer)
            findings.extend(raw.get("findings") or [])
            urls_tested += int(raw.get("urls_tested") or 0)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"chain {chain.name}: {type(exc).__name__}: {exc}")
        if mutate:
            try:
                from shroodler.workflow import run_workflow_mutations

                findings.extend(
                    run_workflow_mutations(chain, config=config, pacer=pacer)
                )
            except Exception as exc:  # noqa: BLE001
                errors.append(f"workflow {chain.name}: {type(exc).__name__}: {exc}")
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
    from shroodler.probes.auth_bypass import probe_auth_bypass
    from shroodler.probes.cache_poisoning import probe_cache_poisoning
    from shroodler.probes.crlf import probe_crlf
    from shroodler.probes.dom_xss import probe_dom_xss, spa_search_view_url
    from shroodler.probes.enum_id import probe_enumerable_id
    from shroodler.probes.file_upload import probe_file_upload
    from shroodler.probes.graphql import probe_graphql
    from shroodler.probes.host_header import hostname_of, probe_host_header
    from shroodler.probes.idor import probe_idor
    from shroodler.probes.jwt import probe_jwt
    from shroodler.probes.mass_assignment import probe_mass_assignment
    from shroodler.probes.nosql import probe_nosql
    from shroodler.probes.open_redirect import probe_open_redirect
    from shroodler.probes.path_traversal import probe_path_traversal
    from shroodler.probes.prototype_pollution import probe_prototype_pollution
    from shroodler.probes.race_condition import probe_race_condition
    from shroodler.probes.rate_limit import probe_rate_limit, probe_rate_limit_bypass
    from shroodler.probes.smuggling import hostname_of as smuggle_host
    from shroodler.probes.smuggling import probe_smuggling
    from shroodler.probes.sqli import probe_sqli
    from shroodler.probes.ssrf import probe_ssrf
    from shroodler.probes.ssti import probe_ssti
    from shroodler.probes.unauth_exposure import probe_unauth_exposure
    from shroodler.probes.websocket import probe_websocket
    from shroodler.probes.xss import probe_xss
    from shroodler.probes.xxe import probe_xxe

    findings: list[Any] = []
    errors: list[str] = []
    seen_hosts: set[str] = set()
    seen_cache: set[str] = set()
    seen_graphql: set[str] = set()
    seen_smuggle: set[str] = set()
    seen_rl: set[str] = set()
    seen_unauth: set[str] = set()
    gate = threading.Lock()

    def _claim(bucket: set[str], key: str) -> bool:
        with gate:
            if not key or key in bucket:
                return False
            bucket.add(key)
            return True

    def _probe_url(index: int, url: str, dest: list | None = None) -> None:
        def _run(label: str, fn) -> None:
            try:
                got = fn() or []
            except Exception as exc:  # noqa: BLE001 - per-probe, must continue
                with gate:
                    errors.append(f"{url} {label}: {type(exc).__name__}: {exc}")
                return
            if dest is None:
                with gate:
                    findings.extend(got)
            else:
                dest.extend(got)

        if not _in_target_origin(url, config.target):
            return
        if not _url_in_program_scope(url, state, config):
            return
        emit_log_entry(
            {
                "iteration": int(getattr(config, "_iteration", 0) or 0),
                "action": "ProbeAction",
                "progress": f"{index}/{len(action.urls)}",
                "url": url,
            }
        )
        meta = state.endpoints.get(url) or {}
        method, params = _probe_params(url, meta)
        view_url = str(meta.get("view_url") or "")
        ghost_or_auth = (
            str(meta.get("source") or "") == "js-analysis"
            or bool(meta.get("auth_required"))
        )
        # Owner session only. Peer/anon IDOR still uses the separate peer arg.
        hdr = owner
        jwt_cookie = cookie_header
        jwt_auth = auth_header
        if ghost_or_auth:
            hdr = cookie_header or auth_header or owner
            jwt_cookie = cookie_header or hdr
            jwt_auth = auth_header
        if config.probe_sqli and method in {"GET", "POST"} and params:
            _run(
                "sqli",
                lambda: probe_sqli(
                    url,
                    method,
                    params,
                    hdr,
                    pacer=pacer,
                    state=state,
                    oob=getattr(config, "_oob", None),
                    time_based=bool(getattr(config, "probe_time_sqli", True)),
                ),
            )
        if config.probe_sqli and method in {"POST", "PUT"} and params:
            _run(
                "auth-bypass",
                lambda: probe_auth_bypass(url, method, params, hdr, pacer=pacer),
            )
        if config.probe_nosql and method in {"GET", "POST", "PUT"} and params:
            _run(
                "nosqli",
                lambda: probe_nosql(
                    url,
                    method,
                    params,
                    hdr,
                    pacer=pacer,
                    state=state,
                ),
            )
        if config.probe_xss and method in {"GET", "POST", "PUT", "PATCH"} and params:
            _run(
                "xss",
                lambda: probe_xss(
                    url,
                    method,
                    params,
                    hdr,
                    view_url=view_url,
                    pacer=pacer,
                    state=state,
                ),
            )
        if config.probe_path_traversal:
            _run(
                "path-traversal",
                lambda: probe_path_traversal(url, params, hdr, pacer=pacer),
            )
        if config.probe_jwt and (jwt_cookie or jwt_auth):
            _run(
                "jwt",
                lambda: probe_jwt(
                    url, jwt_cookie, jwt_auth, pacer=pacer, state=state
                ),
            )
        if config.probe_idor and peer:
            _run("idor", lambda: probe_idor(url, hdr, peer, pacer=pacer))
        if config.run_ssrf and method in {"GET", "POST"} and params:
            _run(
                "ssrf",
                lambda: probe_ssrf(
                    url,
                    method,
                    params,
                    hdr,
                    pacer=pacer,
                    state=state,
                    oob=getattr(config, "_oob", None),
                ),
            )
        if config.run_open_redirect and method in {"GET", "POST"} and params:
            _run(
                "open-redirect",
                lambda: probe_open_redirect(
                    url, method, params, hdr, pacer=pacer, state=state
                ),
            )
        if config.run_host_header:
            host = hostname_of(url)
            if host and _claim(seen_hosts, host):
                _run(
                    "host-header",
                    lambda: probe_host_header(url, hdr, pacer=pacer, state=state),
                )
        if config.run_cache_poisoning:
            host = hostname_of(url)
            if host and _claim(seen_cache, host):
                _run(
                    "cache-poisoning",
                    lambda: probe_cache_poisoning(url, hdr, pacer=pacer, state=state),
                )
        if config.run_ssti and method in {"GET", "POST"} and params:
            _run(
                "ssti",
                lambda: probe_ssti(url, method, params, hdr, pacer=pacer, state=state),
            )
        if config.run_file_upload and method in {"POST", "PUT"} and params:
            _run(
                "file-upload",
                lambda: probe_file_upload(url, method, params, hdr, pacer=pacer, state=state),
            )
        if (
            (config.run_race_condition or getattr(config, "aggressive", False))
            and method in {"POST", "PUT", "PATCH", "DELETE"}
            and params
        ):
            _run(
                "race-condition",
                lambda: probe_race_condition(url, method, params, hdr, pacer=pacer, state=state),
            )
        if config.run_xxe and method in {"GET", "POST"}:
            content_type = str(meta.get("content_type") or meta.get("content-type") or "")
            _run(
                "xxe",
                lambda: probe_xxe(
                    url,
                    method,
                    params,
                    hdr,
                    pacer=pacer,
                    content_type=content_type,
                    state=state,
                    oob=getattr(config, "_oob", None),
                ),
            )
        if config.run_graphql:
            origin = origin_of(url)
            if origin and _claim(seen_graphql, origin):
                _run(
                    "graphql",
                    lambda: probe_graphql(url, hdr, pacer=pacer, state=state),
                )
        if config.run_crlf and method in {"GET", "POST", "PUT", "PATCH"}:
            _run("crlf", lambda: probe_crlf(url, method, params, hdr, pacer=pacer))
        if config.run_prototype_pollution:
            content_type = str(meta.get("content_type") or meta.get("content-type") or "")
            _run(
                "prototype-pollution",
                lambda: probe_prototype_pollution(
                    url,
                    method,
                    params,
                    hdr,
                    pacer=pacer,
                    content_type=content_type,
                ),
            )
        if method in {"GET", "POST"}:
            searchish = _looks_like_search_probe(url, params)
            auto_search = bool(config.probe_xss) and searchish
            if config.run_dom_xss or auto_search:
                probe_params = _ensure_q_param(params) if searchish else list(params)
                if probe_params:
                    _run(
                        "dom-xss",
                        lambda u=url, m=method, p=probe_params, h=hdr: probe_dom_xss(
                            u, m, p, h, pacer=pacer
                        ),
                    )
                    spa_url = spa_search_view_url(url)
                    if spa_url:
                        spa_params = _ensure_q_param(probe_params)
                        _run(
                            "dom-xss",
                            lambda su=spa_url, sp=spa_params, m=method, h=hdr: (
                                probe_dom_xss(su, m, sp, h, pacer=pacer)
                            ),
                        )
        if config.run_rate_limit and _claim(seen_rl, url):
            _run(
                "rate-limit",
                lambda: probe_rate_limit(url, method, hdr, pacer=pacer),
            )
            _run(
                "rate-limit-bypass",
                lambda: probe_rate_limit_bypass(url, method, hdr, pacer=pacer),
            )
        if (
            getattr(config, "run_unauth_exposure", True)
            and method == "GET"
            and _claim(seen_unauth, url)
        ):
            _run(
                "unauth-exposure",
                lambda: probe_unauth_exposure(url, method, pacer=pacer),
            )
            _run(
                "enumerable-id",
                lambda: probe_enumerable_id(url, method, hdr, pacer=pacer),
            )
        if config.run_mass_assignment and method in {"POST", "PUT", "PATCH"}:
            content_type = str(meta.get("content_type") or meta.get("content-type") or "")
            _run(
                "mass-assignment",
                lambda: probe_mass_assignment(
                    url, method, hdr, pacer=pacer, content_type=content_type
                ),
            )
        if config.run_smuggling:
            host = smuggle_host(url)
            if host and _claim(seen_smuggle, host):
                _run(
                    "smuggling",
                    lambda: probe_smuggling(
                        url,
                        hdr,
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

            def _ws_probe(u=url, src="\n".join(js_bits), cookie=hdr):
                hits, found = probe_websocket(
                    u,
                    cookie,
                    pacer=pacer,
                    js_source=src,
                    base_url=config.target,
                )
                existing = list(getattr(state, "websocket_endpoints", None) or [])
                for item in found:
                    if item not in existing:
                        existing.append(item)
                with gate:
                    current = list(getattr(state, "websocket_endpoints", None) or [])
                    for item in existing:
                        if item not in current:
                            current.append(item)
                    state.websocket_endpoints = current
                return hits

            _run("websocket", _ws_probe)

    urls = list(action.urls)
    if bool(getattr(config, "aggressive", False)) and len(urls) > 1:
        # Aggressive: probe URLs concurrently, each with its own keep-alive
        # client. copy_context carries the bound login session into workers.
        import concurrent.futures
        from contextvars import copy_context

        from shroodler.probes.common import aggressive_client, use_aggressive_client

        def _worker(pair: tuple[int, str]) -> None:
            client = aggressive_client(timeout=_AGG_TIMEOUT)
            try:
                with use_aggressive_client(client):
                    _probe_url(pair[0], pair[1])
            finally:
                client.close()

        pairs = list(enumerate(urls, start=1))
        with concurrent.futures.ThreadPoolExecutor(max_workers=_AGG_WORKERS) as ex:
            list(ex.map(lambda pr: copy_context().run(_worker, pr), pairs))
    else:
        pairs = list(enumerate(urls, start=1))
        if len(pairs) <= 1 or _PROBE_WORKERS <= 1:
            for index, url in pairs:
                _probe_url(index, url)
        else:
            # Several URLs in flight. Each request still waits on `pacer`.
            import concurrent.futures

            def _one(pair: tuple[int, str]) -> list:
                local: list = []
                _probe_url(pair[0], pair[1], local)
                return local

            with concurrent.futures.ThreadPoolExecutor(max_workers=_PROBE_WORKERS) as ex:
                for local in ex.map(_one, pairs):
                    findings.extend(local)

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

    def _probe_row(row: dict, probe_pacer: Pacer) -> list[Any]:
        return probe_openapi_endpoints(
            [row], cookie_header=owner, peer_cookie=peer, pacer=probe_pacer
        )

    def _probe_row_pooled(row: dict) -> list[Any]:
        # One keep-alive HTTP/2 client reused across this endpoint's probes,
        # timing out sooner than the default 8s.
        from shroodler.probes.common import aggressive_client

        client = aggressive_client(timeout=_AGG_TIMEOUT)
        try:
            return probe_openapi_endpoints(
                [row],
                cookie_header=owner,
                peer_cookie=peer,
                pacer=Pacer(0.0),
                client=client,
            )
        finally:
            client.close()

    try:
        rows = list(action.endpoints or [])
        if bool(getattr(config, "aggressive", False)) and len(rows) > 1:
            # Aggressive: probe endpoints concurrently, each unpaced. copy_context
            # carries the bound login session (a ContextVar) into the workers.
            import concurrent.futures
            from contextvars import copy_context

            with concurrent.futures.ThreadPoolExecutor(max_workers=_AGG_WORKERS) as ex:
                fut_to_row = {
                    ex.submit(copy_context().run, _probe_row_pooled, row): row
                    for row in rows
                }
                for fut in concurrent.futures.as_completed(fut_to_row):
                    row = fut_to_row[fut]
                    url = str(row.get("url") or "")
                    try:
                        findings.extend(fut.result())
                    except Exception as exc:  # noqa: BLE001 - one endpoint must not stop the rest
                        errors.append(f"{url} openapi-probe: {type(exc).__name__}: {exc}")
                    if url:
                        tested.append(url)
                        row["tested_payload"] = True
        elif len(rows) <= 1 or _PROBE_WORKERS <= 1:
            for row in rows:
                url = str(row.get("url") or "")
                try:
                    findings.extend(_probe_row(row, pacer))
                except Exception as exc:  # noqa: BLE001 - per-endpoint, loop must continue
                    errors.append(f"{url} openapi-probe: {type(exc).__name__}: {exc}")
                if url:
                    tested.append(url)
                    row["tested_payload"] = True
        else:
            import concurrent.futures

            def _one(row: dict) -> tuple[dict, str, list, str | None]:
                url = str(row.get("url") or "")
                try:
                    return row, url, _probe_row(row, pacer), None
                except Exception as exc:  # noqa: BLE001 - per-endpoint, loop must continue
                    return row, url, [], f"{url} openapi-probe: {type(exc).__name__}: {exc}"

            with concurrent.futures.ThreadPoolExecutor(
                max_workers=min(_PROBE_WORKERS, len(rows))
            ) as ex:
                for row, url, got, err in ex.map(_one, rows):
                    if got:
                        findings.extend(got)
                    if err:
                        errors.append(err)
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



def _execute_waf_detect(
    action: WafDetectAction,
    state: ProgramState,
    config: AgentConfig,
    pacer: Pacer,
) -> dict[str, Any]:
    from shroodler.waf_detect import WafResult, detect_waf, finding_from_result

    config._waf_detect_done = True
    errors: list[str] = []
    findings: list[Any] = []
    url = str(config.target or "")
    try:
        import httpx

        async def _run() -> Any:
            async with httpx.AsyncClient(
                timeout=8.0, follow_redirects=False
            ) as client:
                return await detect_waf(url, client, pacer=pacer)

        result = asyncio.run(_run())
        state.waf_detected = bool(result.detected)
        state.waf_vendor = result.vendor
        findings.append(finding_from_result(result, url))
    except Exception as exc:  # noqa: BLE001
        errors.append(f"waf-detect: {type(exc).__name__}: {exc}")
        state.waf_detected = False
        state.waf_vendor = None
        findings.append(
            finding_from_result(
                WafResult(
                    detected=False,
                    vendor=None,
                    confidence=0,
                    block_status=None,
                    evidence=errors[-1],
                ),
                url,
            )
        )
    added = _merge_findings(state, findings)
    out: dict[str, Any] = {
        "pages_crawled": 0,
        "findings_added": added,
        "urls_tested": 1,
        "waf_detected": bool(getattr(state, "waf_detected", False)),
        "waf_vendor": getattr(state, "waf_vendor", None),
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



def _run_llm_verify(
    state: ProgramState, config: AgentConfig, pacer: Pacer, log: list[dict[str, Any]]
) -> None:
    """LLM autoconfirm: re-check tentative findings against fresh evidence,
    confirming, downgrading, or dropping false positives. Never raises."""
    from shroodler.llm_provider import llm_api_key_env, provider_requires_api_key

    provider = getattr(config, "llm_provider", "deepseek")
    env_name = llm_api_key_env(provider)
    if provider_requires_api_key(provider) and not os.environ.get(env_name):
        emit_log_entry({"warning": "llm-verify-skipped", "reason": f"{env_name} missing"})
        return
    try:
        from shroodler.llm_agent.payloads import auto_verify_pending

        tally = auto_verify_pending(state, config, pacer, None)
    except Exception as exc:  # noqa: BLE001 - verification must never break the run
        emit_log_entry({"warning": "llm-verify-error", "reason": f"{type(exc).__name__}: {exc}"})
        return
    entry = {"action": "llm-verify", "result": tally}
    log.append(entry)
    emit_log_entry(entry)



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
    if isinstance(action, WafDetectAction):
        return _execute_waf_detect(action, state, config, clock)
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

