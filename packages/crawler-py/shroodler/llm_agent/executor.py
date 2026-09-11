"""Map Claude tool choices onto existing Shroodler implementations."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlencode, urlparse, urlunparse

import httpx

from shroodler.llm_agent.planner import PlannerDecision
from shroodler.llm_agent.probe_memory import ProbeMemory, ProbeRecord, normalise_url
from shroodler.llm_agent.tools import tool_by_name
from shroodler.pacer import Pacer
from shroodler.probes.common import body_text, request

_FETCH_BODY_CAP = 2000
_PROBE_TYPE_BY_TOOL = {
    "probe_sqli": "sqli",
    "probe_xss": "xss",
    "probe_idor": "idor",
    "probe_ssrf": "ssrf",
    "probe_open_redirect": "open_redirect",
    "probe_path_traversal": "path_traversal",
    "probe_ssti": "ssti",
    "probe_host_header": "host_header",
    "probe_jwt": "jwt",
    "probe_graphql": "graphql",
}


@dataclass
class ToolResult:
    findings_added: int = 0
    summary: str = ""
    raw_output: dict[str, Any] = field(default_factory=dict)
    done: bool = False


def _params_of(decision: PlannerDecision) -> dict[str, Any]:
    return dict(decision.params or {})


def _probe_url_and_param(decision: PlannerDecision) -> tuple[str, str | None]:
    params = _params_of(decision)
    url = str(params.get("url") or params.get("target_url") or "").strip()
    raw = params.get("param")
    if raw is None or str(raw).strip() in {"", "null", "None"}:
        return url, None
    return url, str(raw).strip()


def _finding_ids(findings: list[Any]) -> list[str]:
    ids: list[str] = []
    for item in findings or []:
        fid = getattr(item, "id", None)
        if fid is None and isinstance(item, dict):
            fid = item.get("id")
        if fid:
            ids.append(str(fid))
    return ids


def _classify_probe_result(result: ToolResult) -> tuple[str, str | None]:
    raw = result.raw_output if isinstance(result.raw_output, dict) else {}
    err = str(raw.get("error") or "")
    blob = f"{err} {result.summary or ''}".lower()
    if raw.get("skipped"):
        return "skipped", None
    if "timeout" in blob:
        status = "timeout"
    elif err:
        status = "error"
    elif int(result.findings_added or 0) >= 1:
        status = "finding"
    else:
        status = "no-finding"
    finding_id = None
    if status == "finding":
        ids = raw.get("finding_ids")
        if isinstance(ids, list) and ids:
            finding_id = str(ids[0])
        elif isinstance(ids, str) and ids:
            finding_id = ids
    return status, finding_id


def _skip_if_already_tried(
    name: str,
    decision: PlannerDecision,
    probe_memory: ProbeMemory | None,
) -> ToolResult | None:
    if probe_memory is None:
        return None
    probe_type = _PROBE_TYPE_BY_TOOL.get(name)
    if not probe_type:
        return None
    url, param = _probe_url_and_param(decision)
    if not url:
        return None
    try:
        pattern = normalise_url(url)
        if not probe_memory.already_tried(pattern, probe_type, param):
            return None
    except Exception:  # noqa: BLE001 - never block the probe
        return None
    return ToolResult(
        findings_added=0,
        summary=f"skipped — already tried {probe_type} on {pattern}",
        raw_output={
            "skipped": True,
            "reason": "already tried",
            "url": url,
            "param": param,
            "probe_type": probe_type,
            "endpoint_pattern": pattern,
        },
    )


def _remember_probe(
    name: str,
    decision: PlannerDecision,
    result: ToolResult,
    probe_memory: ProbeMemory | None,
) -> None:
    if probe_memory is None:
        return
    probe_type = _PROBE_TYPE_BY_TOOL.get(name)
    if not probe_type:
        return
    url, param = _probe_url_and_param(decision)
    if not url:
        return
    status, finding_id = _classify_probe_result(result)
    if status == "skipped":
        return
    try:
        probe_memory.record(
            ProbeRecord(
                endpoint_pattern=normalise_url(url),
                probe_type=probe_type,
                param_name=param,
                result=status,
                tried_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                finding_id=finding_id,
            )
        )
    except Exception:  # noqa: BLE001 - memory must not break the agent
        return


def _one_param(
    url: str,
    param: str,
    state: Any,
    current_value: str = "",
) -> tuple[str, list[dict]]:
    from shroodler.agent import _probe_params

    meta = (getattr(state, "endpoints", None) or {}).get(url) or {}
    method, params = _probe_params(url, meta)
    wanted = str(param or "").strip()
    if wanted:
        matching = [item for item in params if item.get("name") == wanted]
        if matching:
            if current_value:
                matching = [{**matching[0], "value": str(current_value)}]
            return method, matching
        return method, [
            {"name": wanted, "value": str(current_value or ""), "in": "query"}
        ]
    return method, params


def _auth(config: Any) -> tuple[str, str]:
    from shroodler.agent import _probe_auth_headers

    return _probe_auth_headers(config)


def _summarize_findings(findings: list[Any], default: str) -> str:
    ids: list[str] = []
    for item in findings or []:
        fid = getattr(item, "id", None)
        if fid is None and isinstance(item, dict):
            fid = item.get("id")
        if fid:
            ids.append(str(fid))
    if ids:
        return f"found {', '.join(ids[:6])}"
    return default


def _merge(state: Any, findings: list[Any]) -> int:
    from shroodler.agent import _merge_findings

    return _merge_findings(state, findings)


def _mark(state: Any, urls: list[str], flag: str) -> None:
    from shroodler import program

    if urls:
        program.mark_tested(state, urls, flag)


def _crawl(decision: PlannerDecision, state: Any, config: Any, pacer: Pacer) -> ToolResult:
    from shroodler.agent import CrawlAction, _execute_crawl

    params = _params_of(decision)
    url = params.get("url")
    if url is None or str(url).strip() in {"", "null", "None"}:
        url = config.target
    raw = _execute_crawl(CrawlAction(urls=[str(url)]), state, config, pacer)
    added = int(raw.get("findings_added") or 0)
    pages = int(raw.get("pages_crawled") or 0)
    new_ep = int(raw.get("new_endpoints") or 0)
    return ToolResult(
        findings_added=added,
        summary=f"crawled {url} pages={pages} new_endpoints={new_ep} findings={added}",
        raw_output=raw,
    )


def _probe(
    name: str,
    decision: PlannerDecision,
    state: Any,
    config: Any,
    pacer: Pacer,
    owner_client: httpx.Client | None,
) -> ToolResult:
    params = _params_of(decision)
    url = str(params.get("url") or "")
    if not url:
        return ToolResult(summary=f"{name} missing url", raw_output={"error": "missing url"})
    param = str(params.get("param") or "")
    method_override = str(params.get("method") or "").upper()
    current = str(params.get("current_value") or "")
    method, one = _one_param(url, param, state, current)
    if method_override in {"GET", "POST"}:
        method = method_override
    owner, peer = _auth(config)
    auth_header = owner if owner.lower().startswith("authorization:") else ""
    cookie_header = "" if auth_header else owner
    findings: list[Any] = []
    try:
        if name == "probe_sqli":
            from shroodler.probes.sqli import probe_sqli

            findings = probe_sqli(
                url, method, one, owner, client=owner_client, pacer=pacer
            )
        elif name == "probe_xss":
            from shroodler.probes.xss import probe_xss

            meta = (getattr(state, "endpoints", None) or {}).get(url) or {}
            findings = probe_xss(
                url,
                method,
                one,
                owner,
                view_url=str(meta.get("view_url") or ""),
                client=owner_client,
                pacer=pacer,
            )
        elif name == "probe_idor":
            from shroodler.probes.idor import probe_idor

            findings = probe_idor(
                url, owner, peer, client=owner_client, pacer=pacer
            )
        elif name == "probe_ssrf":
            from shroodler.probes.ssrf import probe_ssrf

            findings = probe_ssrf(
                url, method, one, owner, client=owner_client, pacer=pacer
            )
        elif name == "probe_open_redirect":
            from shroodler.probes.open_redirect import probe_open_redirect

            findings = probe_open_redirect(
                url, method, one, owner, client=owner_client, pacer=pacer
            )
        elif name == "probe_path_traversal":
            from shroodler.probes.path_traversal import probe_path_traversal

            findings = probe_path_traversal(
                url, one, owner, client=owner_client, pacer=pacer
            )
        elif name == "probe_ssti":
            from shroodler.probes.ssti import probe_ssti

            findings = probe_ssti(
                url, method, one, owner, client=owner_client, pacer=pacer
            )
        elif name == "probe_host_header":
            from shroodler.probes.host_header import probe_host_header

            findings = probe_host_header(url, owner, client=owner_client, pacer=pacer)
        elif name == "probe_jwt":
            from shroodler.probes.jwt import probe_jwt

            findings = probe_jwt(
                url, cookie_header, auth_header, client=owner_client, pacer=pacer
            )
        elif name == "probe_graphql":
            from shroodler.probes.graphql import probe_graphql

            findings = probe_graphql(url, owner, client=owner_client, pacer=pacer)
        else:
            return ToolResult(summary=f"unknown probe {name}", raw_output={"error": name})
    except Exception as exc:  # noqa: BLE001 - fail closed per tool
        return ToolResult(
            summary=f"{name} error: {type(exc).__name__}: {exc}",
            raw_output={"error": f"{type(exc).__name__}: {exc}"},
        )
    added = _merge(state, findings)
    _mark(state, [url], "tested_payload")
    return ToolResult(
        findings_added=added,
        summary=_summarize_findings(findings, f"{name} on {url} found nothing"),
        raw_output={
            "findings": len(findings),
            "url": url,
            "param": param,
            "finding_ids": _finding_ids(findings),
        },
    )


def _check_authz(
    decision: PlannerDecision,
    state: Any,
    config: Any,
    pacer: Pacer,
) -> ToolResult:
    from shroodler import program
    from shroodler.agent import _allow_external, run_authz_diff

    url = str(_params_of(decision).get("url") or "")
    if not url:
        return ToolResult(summary="check_authz missing url", raw_output={"error": "missing url"})
    pacer.wait()
    raw = run_authz_diff(
        [url],
        higher_priv=str(config.higher_priv_jar or ""),
        lower_priv=str(config.lower_priv_jar or ""),
        target=config.target,
        allow_external=_allow_external(config.target),
        owner_cookie=config.owner_cookie,
        peer_cookie=config.peer_cookie,
        endpoint_meta={url: (state.endpoints.get(url) or {})},
    )
    added = _merge(state, list(raw.get("findings") or []))
    program.mark_tested(state, [url], "tested_authz")
    return ToolResult(
        findings_added=added,
        summary=_summarize_findings(raw.get("findings") or [], f"check_authz {url} found nothing"),
        raw_output=raw if isinstance(raw, dict) else {"result": raw},
    )


def _with_query(url: str, extra: dict[str, Any]) -> str:
    parsed = urlparse(url)
    existing = parsed.query
    added = urlencode({str(k): str(v) for k, v in extra.items()}, doseq=True)
    query = "&".join(p for p in (existing, added) if p)
    return urlunparse(parsed._replace(query=query))


def _fetch_and_read(
    decision: PlannerDecision,
    config: Any,
    pacer: Pacer,
    owner_client: httpx.Client | None,
) -> ToolResult:
    params = _params_of(decision)
    url = str(params.get("url") or "")
    if not url:
        return ToolResult(summary="fetch_and_read missing url", raw_output={"error": "missing url"})
    method = str(params.get("method") or "GET").upper() or "GET"
    extra = params.get("params")
    kwargs: dict[str, Any] = {}
    target = url
    if isinstance(extra, dict) and extra:
        if method == "GET":
            target = _with_query(url, extra)
        else:
            kwargs["data"] = {str(k): str(v) for k, v in extra.items()}
    owner, _peer = _auth(config)
    resp = request(
        method,
        target,
        cookie_header=owner,
        client=owner_client,
        pacer=pacer,
        follow_redirects=True,  # recon: resolve the real page, don't stall on a 3xx
        **kwargs,
    )
    if resp is None:
        return ToolResult(
            summary=f"fetch_and_read {url} failed",
            raw_output={"error": "transport", "url": url},
        )
    body = body_text(resp)[:_FETCH_BODY_CAP]
    status = int(getattr(resp, "status_code", 0) or 0)
    final_url = str(getattr(resp, "url", "") or "")
    redirected = final_url and final_url != target
    summary = f"fetch_and_read {method} {url} status={status} bytes={len(body)}"
    if redirected:
        summary += f" (followed redirect to {final_url})"
    return ToolResult(
        findings_added=0,
        summary=summary,
        raw_output={
            "url": url,
            "final_url": final_url,
            "method": method,
            "status_code": status,
            "body": body,
        },
    )


def _hypothesise(decision: PlannerDecision, state: Any) -> ToolResult:
    params = _params_of(decision)
    entry = {
        "hypothesis": str(params.get("hypothesis") or ""),
        "target_url": str(params.get("target_url") or ""),
        "reasoning": str(params.get("reasoning") or ""),
    }
    hyps = getattr(state, "hypotheses", None)
    if hyps is None:
        state.hypotheses = []
        hyps = state.hypotheses
    hyps.append(entry)
    text = entry["hypothesis"] or "(empty)"
    return ToolResult(
        findings_added=0,
        summary=f"hypothesise: {text[:160]}",
        raw_output=entry,
    )


def _remember_jwt_fact(state: Any, result: ToolResult) -> None:
    """Record the JWT algorithm as a cross-engagement fact. Never raises."""
    raw = result.raw_output if isinstance(result.raw_output, dict) else {}
    if raw.get("kind") != "jwt":
        return
    alg = str(raw.get("alg") or "").strip()
    if not alg:
        return
    try:
        from shroodler.llm_agent.engagement_memory import record_fact

        record_fact(state, "jwt_alg", alg, source="decode_token")
    except Exception:  # noqa: BLE001 - memory must not break the loop
        return


def _snapshot_engagement_memory(state: Any, config: Any, probe_memory: Any) -> None:
    try:
        from shroodler.llm_agent.engagement_memory import snapshot

        snapshot(state, config, probe_memory)
    except Exception:  # noqa: BLE001
        return


def _auto_verify_before_report(
    state: Any, config: Any, pacer: Pacer, owner_client: httpx.Client | None
) -> None:
    """Verify tentative findings before the report unless disabled. Never raises."""
    if not bool(getattr(config, "llm_auto_verify", True)):
        return
    try:
        from shroodler.llm_agent.payloads import auto_verify_pending

        auto_verify_pending(state, config, pacer, owner_client)
    except Exception:  # noqa: BLE001 - report must still generate
        return


def _report(state: Any) -> ToolResult:
    from shroodler.agent import _execute_report

    raw = _execute_report(state)
    confirmed = int(raw.get("confirmed") or 0)
    return ToolResult(
        findings_added=0,
        summary=f"report confirmed={confirmed}",
        raw_output=raw,
        done=True,
    )


def execute_tool(
    decision: PlannerDecision,
    state: Any,
    config: Any,
    owner_client: httpx.Client | None,
    peer_client: httpx.Client | None,
    pacer: Pacer,
    probe_memory: ProbeMemory | None = None,
) -> ToolResult:
    """Run one planner decision. Does not duplicate probe logic."""
    _ = peer_client
    if decision is None or decision.fallback or not decision.action:
        return ToolResult(
            summary=decision.fallback_reason if decision else "no decision",
            raw_output={"fallback": True},
        )
    name = decision.action
    if tool_by_name(name) is None:
        return ToolResult(
            summary=f"unknown tool {name}",
            raw_output={"error": "unknown tool"},
        )
    try:
        if name == "crawl":
            return _crawl(decision, state, config, pacer)
        if name.startswith("probe_"):
            skipped = _skip_if_already_tried(name, decision, probe_memory)
            if skipped is not None:
                return skipped
            result = _probe(name, decision, state, config, pacer, owner_client)
            _remember_probe(name, decision, result, probe_memory)
            return result
        if name == "check_authz":
            return _check_authz(decision, state, config, pacer)
        if name == "fetch_and_read":
            return _fetch_and_read(decision, config, pacer, owner_client)
        if name in {"send_request", "compare_responses", "replay_as_user", "decode_token"}:
            from shroodler.llm_agent import http_tools

            if name == "send_request":
                return http_tools.send_request(decision, config, pacer, owner_client)
            if name == "compare_responses":
                return http_tools.compare_responses(decision, config, pacer, owner_client)
            if name == "replay_as_user":
                return http_tools.replay_as_user(decision, config, pacer, owner_client)
            result = http_tools.decode_token(decision)
            _remember_jwt_fact(state, result)
            return result
        if name in {"craft_payloads", "verify_finding", "analyze_logic"}:
            from shroodler.llm_agent import payloads

            if name == "craft_payloads":
                return payloads.craft_payloads(decision, state, config, pacer, owner_client)
            if name == "verify_finding":
                return payloads.verify_finding(decision, state, config, pacer, owner_client)
            return payloads.analyze_logic(decision, state, config)
        if name == "test_hypothesis":
            from shroodler.llm_agent import hypotheses

            return hypotheses.test_hypothesis(
                decision, state, config, pacer, owner_client, probe_memory=probe_memory
            )
        if name == "hypothesise":
            return _hypothesise(decision, state)
        if name == "report":
            _auto_verify_before_report(state, config, pacer, owner_client)
            _snapshot_engagement_memory(state, config, probe_memory)
            return _report(state)
    except Exception as exc:  # noqa: BLE001
        result = ToolResult(
            summary=f"{name} error: {type(exc).__name__}: {exc}",
            raw_output={"error": f"{type(exc).__name__}: {exc}"},
        )
        if name.startswith("probe_"):
            _remember_probe(name, decision, result, probe_memory)
        return result
    return ToolResult(summary=f"unhandled tool {name}", raw_output={"error": name})
