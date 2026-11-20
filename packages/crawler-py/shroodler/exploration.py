"""Asset ledger, exploration graph, and capped worker traces.

The asset list says what exists. The exploration graph says what was tried
and what it produced. Anchors tie an intent or a fact to an asset. Traces
hold bounded raw output beside state.json so a later iteration can search
it without bloating the state file.

Apache-2.0. This is Shroodler's own model of an engagement loop. It does
not copy another project's code.
"""

from __future__ import annotations

import json
import uuid
from typing import Any
from urllib.parse import urlparse

from shroodler.program import ProgramState, _endpoint_key, program_dir
from shroodler.util import now_iso

_TRACE_CAP = 200
_TRACE_OUTPUT_CAP = 4096
_NODE_KINDS = frozenset({"goal", "intent", "fact", "finding", "hint"})
_EDGE_KINDS = frozenset({"spawns", "derived_from", "yields", "proves"})


def _nodes(state: ProgramState) -> list[dict[str, Any]]:
    rows = getattr(state, "exploration_nodes", None)
    if rows is None:
        state.exploration_nodes = []
        rows = state.exploration_nodes
    return rows


def _edges(state: ProgramState) -> list[dict[str, Any]]:
    rows = getattr(state, "exploration_edges", None)
    if rows is None:
        state.exploration_edges = []
        rows = state.exploration_edges
    return rows


def _assets(state: ProgramState) -> list[dict[str, Any]]:
    rows = getattr(state, "assets", None)
    if rows is None:
        state.assets = []
        rows = state.assets
    return rows


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:  # noqa: BLE001
        return ""


def service_id(url: str) -> str:
    parsed = urlparse(url)
    scheme = parsed.scheme or "http"
    host = host_of(url)
    return f"service:{scheme}://{host}" if host else ""


def endpoint_asset_id(url: str) -> str:
    key = _endpoint_key(url)
    return f"endpoint:{key}" if key else ""


def asset_ids_for_url(url: str) -> list[str]:
    host = host_of(url)
    out: list[str] = []
    if host:
        out.append(f"host:{host}")
    service = service_id(url)
    if service:
        out.append(service)
    endpoint = endpoint_asset_id(url)
    if endpoint:
        out.append(endpoint)
    return out


def sync_assets(state: ProgramState) -> list[dict[str, Any]]:
    """Project hosts, services, and endpoints from scope and the endpoint map.

    ``tested`` is true once the endpoint has been authz-checked, peer-written,
    or payload-tested. Existing asset rows are updated in place.
    """
    by_id: dict[str, dict[str, Any]] = {}
    for row in _assets(state):
        if isinstance(row, dict) and row.get("id"):
            by_id[str(row["id"])] = dict(row)

    urls: list[str] = []
    for raw in list(getattr(state, "scope_urls", None) or []) + list(state.endpoints):
        text = str(raw or "").strip()
        if text and text not in urls:
            urls.append(text)

    for url in urls:
        host = host_of(url)
        if not host:
            continue
        parsed = urlparse(url)
        scheme = parsed.scheme or "http"
        hid = f"host:{host}"
        sid = f"service:{scheme}://{host}"
        eid = endpoint_asset_id(url)
        meta = state.endpoints.get(_endpoint_key(url)) or state.endpoints.get(url) or {}
        if not isinstance(meta, dict):
            meta = {}
        tested = bool(
            meta.get("tested_payload")
            or meta.get("tested_authz")
            or meta.get("tested_peer_write")
        )
        base = f"{scheme}://{host}"
        _upsert_asset(by_id, hid, kind="host", parent="", url=base, tested=False)
        _upsert_asset(by_id, sid, kind="service", parent=hid, url=base, tested=False)
        if eid:
            _upsert_asset(
                by_id,
                eid,
                kind="endpoint",
                parent=sid,
                url=_endpoint_key(url),
                tested=tested,
            )
    state.assets = [by_id[key] for key in sorted(by_id)]
    return state.assets


def _upsert_asset(
    by_id: dict[str, dict[str, Any]],
    asset_id: str,
    *,
    kind: str,
    parent: str,
    url: str,
    tested: bool,
) -> None:
    row = by_id.get(asset_id)
    if row is None:
        by_id[asset_id] = {
            "id": asset_id,
            "kind": kind,
            "parent": parent,
            "url": url,
            "tested": bool(tested),
        }
        return
    row["kind"] = kind
    row["parent"] = parent or row.get("parent") or ""
    row["url"] = url or row.get("url") or ""
    if tested:
        row["tested"] = True


def ensure_goal(state: ProgramState, target: str) -> str:
    for node in _nodes(state):
        if node.get("kind") == "goal":
            return str(node.get("id") or "")
    node_id = _new_id("goal")
    _nodes(state).append(
        {
            "id": node_id,
            "kind": "goal",
            "key": f"goal:{target}",
            "summary": f"assess {target}",
            "status": "open",
            "asset_ids": asset_ids_for_url(target),
            "urls": [target] if target else [],
        }
    )
    return node_id


def _goal_id(state: ProgramState) -> str:
    for node in _nodes(state):
        if node.get("kind") == "goal" and node.get("id"):
            return str(node["id"])
    return ""


def find_node(state: ProgramState, key: str, *, kind: str | None = None) -> dict[str, Any] | None:
    for node in _nodes(state):
        if str(node.get("key") or "") != key:
            continue
        if kind and node.get("kind") != kind:
            continue
        return node
    return None


def add_edge(state: ProgramState, src: str, dst: str, kind: str) -> None:
    if kind not in _EDGE_KINDS or not src or not dst:
        return
    for edge in _edges(state):
        if edge.get("src") == src and edge.get("dst") == dst and edge.get("kind") == kind:
            return
    _edges(state).append({"src": src, "dst": dst, "kind": kind})


def add_node(
    state: ProgramState,
    *,
    kind: str,
    key: str,
    summary: str,
    status: str = "open",
    asset_ids: list[str] | None = None,
    urls: list[str] | None = None,
    detail: dict[str, Any] | None = None,
) -> str:
    if kind not in _NODE_KINDS:
        raise ValueError(f"unknown exploration node kind {kind!r}")
    existing = find_node(state, key, kind=kind)
    if existing is not None:
        existing["summary"] = summary or existing.get("summary") or ""
        existing["status"] = status or existing.get("status") or "open"
        if asset_ids:
            existing["asset_ids"] = list(asset_ids)
        if urls:
            existing["urls"] = list(urls)
        if detail:
            existing["detail"] = dict(detail)
        return str(existing.get("id") or "")
    node_id = _new_id(kind)
    row: dict[str, Any] = {
        "id": node_id,
        "kind": kind,
        "key": key,
        "summary": summary,
        "status": status,
        "asset_ids": list(asset_ids or []),
        "urls": list(urls or []),
    }
    if detail:
        row["detail"] = dict(detail)
    _nodes(state).append(row)
    return node_id


def record_intent(
    state: ProgramState,
    *,
    key: str,
    summary: str,
    urls: list[str] | None = None,
    status: str = "done",
    fact: str | None = None,
    finding_ids: list[str] | None = None,
    target: str = "",
) -> str:
    """Record an intent and, when it finished, the fact and finding it yielded."""
    sync_assets(state)
    goal = ensure_goal(state, target or (urls[0] if urls else ""))
    assets: list[str] = []
    for url in urls or []:
        for asset_id in asset_ids_for_url(url):
            if asset_id not in assets:
                assets.append(asset_id)
    intent_id = add_node(
        state,
        kind="intent",
        key=key,
        summary=summary,
        status=status,
        asset_ids=assets,
        urls=list(urls or []),
    )
    add_edge(state, goal, intent_id, "spawns")
    if fact:
        fact_id = add_node(
            state,
            kind="fact",
            key=f"fact:{key}",
            summary=fact,
            status="done",
            asset_ids=assets,
            urls=list(urls or []),
        )
        add_edge(state, intent_id, fact_id, "yields")
    for fid in finding_ids or []:
        if not fid:
            continue
        found_id = add_node(
            state,
            kind="finding",
            key=f"finding:{fid}",
            summary=fid,
            status="done",
            asset_ids=assets,
            urls=list(urls or []),
        )
        add_edge(state, intent_id, found_id, "proves")
    return intent_id


def add_hint(state: ProgramState, summary: str, *, urls: list[str] | None = None) -> str:
    """A tool observation that is not a verified finding."""
    key = f"hint:{uuid.uuid4().hex[:12]}"
    assets: list[str] = []
    for url in urls or []:
        assets.extend(asset_ids_for_url(url))
    return add_node(
        state,
        kind="hint",
        key=key,
        summary=(summary or "")[:500],
        status="done",
        asset_ids=assets,
        urls=list(urls or []),
    )


def intent_recorded(state: ProgramState, key: str) -> bool:
    node = find_node(state, key, kind="intent")
    return node is not None and str(node.get("status") or "") in {"open", "done"}


def open_intents(state: ProgramState) -> list[dict[str, Any]]:
    return [
        dict(node)
        for node in _nodes(state)
        if node.get("kind") == "intent" and node.get("status") == "open"
    ]


def untested_assets(state: ProgramState) -> list[dict[str, Any]]:
    sync_assets(state)
    return [
        dict(row)
        for row in _assets(state)
        if row.get("kind") == "endpoint" and not row.get("tested")
    ]


def _workflow_steps(state: ProgramState) -> list[dict[str, str]]:
    from shroodler.workflow_model import infer_workflows_from_state

    out: list[dict[str, str]] = []
    for wf in infer_workflows_from_state(state):
        previous = ""
        for step in wf.steps:
            fact_key = f"step:{wf.name}:{step.method}:{step.action}"
            out.append(
                {
                    "workflow": wf.name,
                    "method": step.method,
                    "url": step.action,
                    "fact_key": fact_key,
                    "prerequisite": previous,
                }
            )
            previous = fact_key
    return out


def _fact_exists(state: ProgramState, key: str) -> bool:
    return find_node(state, key, kind="fact") is not None


def blocked_chain_steps(state: ProgramState) -> list[dict[str, str]]:
    """Later workflow steps whose prerequisite fact has not been recorded."""
    blocked: list[dict[str, str]] = []
    for step in _workflow_steps(state):
        prereq = step.get("prerequisite") or ""
        if prereq and not _fact_exists(state, prereq):
            blocked.append(step)
    return blocked


def ready_chain_step(state: ProgramState) -> dict[str, str] | None:
    """The next workflow step whose prerequisite fact is already present."""
    for step in _workflow_steps(state):
        prereq = step.get("prerequisite") or ""
        if not prereq or not _fact_exists(state, prereq):
            continue
        key = f"chain:{step['workflow']}:{step['method']}:{step['url']}"
        if intent_recorded(state, key):
            continue
        return step
    return None


def endpoint_without_probe_intent(state: ProgramState) -> str | None:
    for url, meta in state.endpoints.items():
        if not isinstance(meta, dict):
            continue
        if meta.get("tested_payload"):
            continue
        if intent_recorded(state, f"probe:{url}"):
            continue
        return str(url)
    return None


def finding_needs_retest(state: ProgramState) -> Any | None:
    for finding in state.findings:
        fid = str(getattr(finding, "id", "") or "")
        url = str(getattr(finding, "url", "") or "")
        if not fid or not url:
            continue
        if intent_recorded(state, f"retest:{fid}:{url}"):
            continue
        return finding
    return None


def next_uncovered(
    state: ProgramState,
    *,
    run_probes: bool,
    dry_run: bool,
) -> dict[str, Any] | None:
    """One uncovered intent after the fixed priority list is exhausted.

    Dry-run keeps the historical priority order, so this returns nothing then.
    A chain step is returned only when its prerequisite fact exists.
    """
    if dry_run:
        return None
    step = ready_chain_step(state)
    if step is not None:
        return {"kind": "chain", **step}
    finding = finding_needs_retest(state)
    if finding is not None:
        return {
            "kind": "retest",
            "finding_id": str(getattr(finding, "id", "") or ""),
            "url": str(getattr(finding, "url", "") or ""),
        }
    if run_probes:
        url = endpoint_without_probe_intent(state)
        if url:
            return {"kind": "probe", "url": url}
    return None


def note_step_facts(state: ProgramState, urls: list[str], *, method: str = "") -> None:
    """When an action touches a workflow step, record the fact later steps need."""
    wanted = {str(url) for url in urls if url}
    if not wanted:
        return
    for step in _workflow_steps(state):
        if step["url"] not in wanted:
            continue
        if method and step["method"] != method.upper():
            continue
        add_node(
            state,
            kind="fact",
            key=step["fact_key"],
            summary=f"completed {step['method']} {step['url']}",
            status="done",
            asset_ids=asset_ids_for_url(step["url"]),
            urls=[step["url"]],
        )


def remember_action(
    state: ProgramState,
    *,
    action: str,
    summary: str,
    urls: list[str] | None = None,
    key: str | None = None,
    finding_ids: list[str] | None = None,
    fact: str | None = None,
    target: str = "",
    method: str = "",
) -> str:
    """Close an intent for one loop action. Never raises."""
    try:
        intent_key = key or f"{action}:{','.join(urls or [])}"
        intent_id = record_intent(
            state,
            key=intent_key,
            summary=summary or action,
            urls=list(urls or []),
            status="done",
            fact=fact or summary,
            finding_ids=list(finding_ids or []),
            target=target,
        )
        note_step_facts(state, list(urls or []), method=method)
        return intent_id
    except Exception:  # noqa: BLE001 - the graph must not break the loop
        return ""


def status_lines(state: ProgramState) -> list[str]:
    """Lines for ``program status``: untested endpoints, blocked steps, open intents."""
    lines: list[str] = []
    untested = untested_assets(state)
    lines.append(f"untested assets: {len(untested)}")
    for asset in untested[:10]:
        lines.append(f"  untested {asset.get('url') or asset.get('id')}")
    blocked = blocked_chain_steps(state)
    lines.append(f"blocked chain steps: {len(blocked)}")
    for step in blocked[:10]:
        lines.append(
            f"  blocked chain {step['workflow']} {step['method']} {step['url']}"
            f" missing={step['prerequisite']}"
        )
    opened = open_intents(state)
    if opened:
        lines.append(f"open intents: {len(opened)}")
        for node in opened[:10]:
            lines.append(f"  open intent {node.get('summary') or node.get('key')}")
    return lines


def traces_path(slug: str):
    return program_dir(slug) / "traces.jsonl"


def append_trace(
    slug: str,
    *,
    action: str,
    output: str,
    argv: list[str] | None = None,
    trace_id: str | None = None,
) -> str:
    """Append one bounded trace and keep the file at the last ``_TRACE_CAP`` lines."""
    if not slug:
        return ""
    path = traces_path(slug)
    path.parent.mkdir(parents=True, exist_ok=True)
    existing: list[str] = []
    if path.is_file():
        existing = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    tid = trace_id or _new_id("trace")
    record = {
        "id": tid,
        "action": action,
        "argv": list(argv or []),
        "output": (output or "")[:_TRACE_OUTPUT_CAP],
        "at": now_iso(),
    }
    existing.append(json.dumps(record, default=str))
    kept = existing[-_TRACE_CAP:]
    path.write_text("\n".join(kept) + "\n", encoding="utf-8")
    return tid


def search_traces(slug: str, query: str, *, limit: int = 20) -> list[dict[str, Any]]:
    needle = (query or "").strip().lower()
    if not slug or not needle:
        return []
    path = traces_path(slug)
    if not path.is_file():
        return []
    hits: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        blob = f"{row.get('action') or ''} {row.get('output') or ''}".lower()
        if needle in blob:
            hits.append(row)
    return hits[-limit:]


# Ranks match the historical checklist order. A lower rank is chosen first.
CHECKLIST_RANK = {
    "login": 10,
    "tls": 20,
    "crawl": 30,
    "js": 40,
    "diff": 50,
    "waf": 60,
    "openapi_discover": 70,
    "auto_register": 80,
    "authz": 90,
    "idor": 100,
    "write_authz": 110,
    "peer_write": 120,
    "content_discover": 130,
    "probe": 140,
    "openapi_probe": 150,
    "business_logic": 160,
    "chain": 170,
    "chain_step": 180,
    "retest": 190,
    "uncovered_probe": 195,
    "report": 200,
}


def schedule_intent(
    state: ProgramState,
    *,
    key: str,
    summary: str,
    rank: int,
    prerequisite: str = "",
    urls: list[str] | None = None,
    live_only: bool = False,
    action: str = "",
    payload: dict[str, Any] | None = None,
    target: str = "",
    improvised: bool = False,
) -> str:
    """Upsert one scheduler intent. Re-opening a still-applicable step is intentional."""
    detail: dict[str, Any] = {
        "rank": int(rank),
        "prerequisite": prerequisite or "",
        "scheduled": True,
        "live_only": bool(live_only),
        "action": action,
        "improvised": bool(improvised),
    }
    if payload:
        detail["payload"] = dict(payload)
    sync_assets(state)
    goal = ensure_goal(state, target or ((urls or [""])[0] if urls else ""))
    assets: list[str] = []
    for url in urls or []:
        for asset_id in asset_ids_for_url(url):
            if asset_id not in assets:
                assets.append(asset_id)
    intent_id = add_node(
        state,
        kind="intent",
        key=key,
        summary=summary,
        status="open",
        asset_ids=assets,
        urls=list(urls or []),
        detail=detail,
    )
    add_edge(state, goal, intent_id, "spawns")
    return intent_id


def close_scheduled_except(state: ProgramState, keep: set[str]) -> None:
    """Close scheduler intents that this pass did not renew."""
    for node in _nodes(state):
        if node.get("kind") != "intent" or node.get("status") != "open":
            continue
        detail = node.get("detail") if isinstance(node.get("detail"), dict) else {}
        if not detail.get("scheduled"):
            continue
        # An improvised attack step survives checklist reseeds until it is executed.
        if detail.get("improvised"):
            continue
        key = str(node.get("key") or "")
        if key not in keep:
            node["status"] = "done"


def prerequisite_met(state: ProgramState, node: dict[str, Any]) -> bool:
    """A step is ready when it has no prerequisite, or that fact or prior intent is done.

    Fact keys (``step:`` / ``fact:``) must exist on the graph. An intent key is
    satisfied once that intent is no longer open, which is how a finished
    checklist step unlocks the next one.
    """
    detail = node.get("detail") if isinstance(node.get("detail"), dict) else {}
    prereq = str(detail.get("prerequisite") or "")
    if not prereq:
        return True
    if prereq.startswith("step:") or prereq.startswith("fact:"):
        if _fact_exists(state, prereq):
            return True
        if prereq.startswith("fact:") and _fact_exists(state, prereq[5:]):
            return True
        return False
    prior = find_node(state, prereq, kind="intent")
    if prior is None or str(prior.get("status") or "") != "open":
        return True
    return _fact_exists(state, f"fact:{prereq}")


IMPROVISED_RANK = 35


def _is_improvised(node: dict[str, Any]) -> bool:
    detail = node.get("detail") if isinstance(node.get("detail"), dict) else {}
    return bool(detail.get("improvised"))


def note_improvised_intent(
    state: ProgramState,
    *,
    summary: str,
    url: str = "",
    prerequisite: str = "",
    action: str = "",
    finding_id: str = "",
    target: str = "",
) -> str:
    """Append one attack step the scheduler will keep across wake-ups.

    Rank sits just after crawl, so login, TLS, and coverage still go first.
    The step is live-only: a dry-run keeps printing the checklist. A second
    step names the first step's key as its prerequisite and stays blocked
    until that step is closed.
    """
    key = f"improvised:{uuid.uuid4().hex[:12]}"
    payload: dict[str, Any] = {"suggested": action or "probe"}
    if finding_id:
        payload["finding_id"] = finding_id
    schedule_intent(
        state,
        key=key,
        summary=(summary or action or "improvised step")[:300],
        rank=IMPROVISED_RANK,
        prerequisite=prerequisite,
        urls=[url] if url else [],
        live_only=True,
        action=action or "probe",
        payload=payload,
        target=target or url,
        improvised=True,
    )
    return key


def ready_improvised(state: ProgramState) -> dict[str, Any] | None:
    """The lowest-rank improvised step whose prerequisite is already met."""
    ready: list[dict[str, Any]] = []
    for node in _nodes(state):
        if node.get("kind") != "intent" or node.get("status") != "open":
            continue
        if not _is_improvised(node):
            continue
        if not prerequisite_met(state, node):
            continue
        ready.append(node)
    if not ready:
        return None
    ready.sort(
        key=lambda node: (
            int((node.get("detail") or {}).get("rank") or 0),
            str(node.get("key") or ""),
        )
    )
    return dict(ready[0])


def close_ready_improvised(state: ProgramState, urls: list[str]) -> str:
    """Close the head improvised step when one of its URLs was just exercised."""
    wanted = {str(url) for url in urls if url}
    if not wanted:
        return ""
    head = ready_improvised(state)
    if head is None:
        return ""
    node_urls = {str(url) for url in (head.get("urls") or []) if url}
    if not node_urls & wanted:
        return ""
    key = str(head.get("key") or "")
    current = find_node(state, key, kind="intent")
    if current is not None:
        current["status"] = "done"
    return key


def pick_ready_intent(
    state: ProgramState,
    *,
    dry_run: bool = False,
    skip_improvised: bool = False,
) -> dict[str, Any] | None:
    """Lowest-rank open scheduler intent whose prerequisite is met.

    Dry-run skips live-only intents (chain steps, retests, extra probes) so the
    printed plan stays the checklist order and makes no requests.
    """
    ready: list[dict[str, Any]] = []
    for node in _nodes(state):
        if node.get("kind") != "intent" or node.get("status") != "open":
            continue
        detail = node.get("detail") if isinstance(node.get("detail"), dict) else {}
        if not detail.get("scheduled"):
            continue
        if skip_improvised and detail.get("improvised"):
            continue
        if dry_run and detail.get("live_only"):
            continue
        if not prerequisite_met(state, node):
            continue
        ready.append(node)
    if not ready:
        return None
    ready.sort(
        key=lambda node: (
            int((node.get("detail") or {}).get("rank") or 0),
            str(node.get("key") or ""),
        )
    )
    return dict(ready[0])


def seed_chain_intents(state: ProgramState) -> list[str]:
    """Persist later workflow steps as intents gated on their prerequisite fact.

    Step 0 has no prerequisite and is not dispatched here. A step whose own
    fact is already recorded stays closed. The intents live on program state,
    so a later process sees the same blocked list.
    """
    keys: list[str] = []
    for step in _workflow_steps(state):
        prereq = step.get("prerequisite") or ""
        if not prereq:
            continue
        if _fact_exists(state, step["fact_key"]):
            continue
        key = f"chain:{step['workflow']}:{step['method']}:{step['url']}"
        schedule_intent(
            state,
            key=key,
            summary=f"chain {step['workflow']} {step['method']} {step['url']}",
            rank=CHECKLIST_RANK["chain_step"],
            prerequisite=prereq,
            urls=[step["url"]],
            live_only=True,
            action="ChainStepAction",
            payload={
                "workflow": step["workflow"],
                "url": step["url"],
                "method": step["method"],
                "prerequisite": prereq,
            },
        )
        keys.append(key)
    return keys


def record_retest_status(
    state: ProgramState,
    *,
    finding_id: str,
    url: str,
    status: str,
    reason: str = "",
) -> None:
    """Write reproduces/fixed/unconfirmable onto the finding and its graph node.

    The original proof is left in place. ``fixed`` drops the finding out of the
    confirmed set the report treats as still open.
    """
    for finding in state.findings:
        if str(getattr(finding, "id", "") or "") != finding_id:
            continue
        if url and str(getattr(finding, "url", "") or "") != url:
            continue
        finding.retest_status = status  # type: ignore[attr-defined]
    add_node(
        state,
        kind="finding",
        key=f"finding:{finding_id}",
        summary=f"{finding_id} {status}",
        status="done",
        urls=[url] if url else [],
        detail={"retest_status": status, "reason": reason},
    )
