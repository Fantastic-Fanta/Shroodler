from __future__ import annotations

import json

import pytest
from shroodler_mcp.tools import (
    _project_root,
    _resolve_safe_path,
    check_idor,
    check_ws_idor,
    diff_since_baseline,
    explain_finding,
    extract_js_routes,
    paced_fetch,
    peer_write,
    reverify_fix,
    scan_route,
)


def test_explain_finding_by_category_fallback():
    result = explain_finding({"category": "secret"})
    assert "Rotate" in result["remediation"]


def test_explain_finding_requires_something():
    with pytest.raises(ValueError):
        explain_finding({})


def test_scan_route_requires_url():
    with pytest.raises(ValueError):
        scan_route({})


def test_scan_route_refuses_external_without_flag():
    with pytest.raises(ValueError):
        scan_route({"url": "https://example.com/"})


def test_check_idor_requires_higher_priv_crawl():
    with pytest.raises(ValueError):
        check_idor({})


def test_diff_since_baseline_clean():
    crawl = {
        "target": "http://x",
        "pages": [{"url": "http://x/a", "status_code": 200, "forms": [], "params": [], "cookies": [], "headers": {}, "js_files": []}],
        "findings": [],
    }
    baseline = {"expected_pages": ["/a"], "expected_findings": []}
    result = diff_since_baseline({"crawl": crawl, "baseline": baseline, "gate": True})
    assert result["clean"] is True
    assert result["errors"] == []


def test_diff_since_baseline_flags_new_finding():
    crawl = {
        "target": "http://x",
        "pages": [],
        "findings": [
            {
                "id": "missing-hsts",
                "severity": "medium",
                "category": "header",
                "url": "http://x/a",
                "description": "d",
                "evidence": None,
            }
        ],
    }
    baseline = {"expected_pages": [], "expected_findings": []}
    result = diff_since_baseline({"crawl": crawl, "baseline": baseline, "gate": True})
    assert result["clean"] is False
    assert any("missing-hsts" in e for e in result["errors"])


def test_resolve_safe_path_allows_file_under_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    f = tmp_path / "scan.json"
    f.write_text("{}")
    assert _resolve_safe_path("scan.json") == f.resolve()


def test_resolve_safe_path_refuses_traversal_outside_cwd(tmp_path, monkeypatch):
    workdir = tmp_path / "work"
    workdir.mkdir()
    outside = tmp_path / "secret.json"
    outside.write_text("{}")
    monkeypatch.chdir(workdir)
    with pytest.raises(ValueError, match="outside the project root"):
        _resolve_safe_path(str(outside))
    with pytest.raises(ValueError):
        _resolve_safe_path("../secret.json")


def test_resolve_safe_path_escape_hatch(tmp_path, monkeypatch):
    workdir = tmp_path / "work"
    workdir.mkdir()
    outside = tmp_path / "secret.json"
    outside.write_text("{}")
    monkeypatch.chdir(workdir)
    monkeypatch.setenv("SHROODLER_MCP_ALLOW_ANY_PATH", "1")
    assert _resolve_safe_path(str(outside)) == outside.resolve()


def test_load_doc_via_path_is_sandboxed(tmp_path, monkeypatch):
    workdir = tmp_path / "work"
    workdir.mkdir()
    outside = tmp_path / "secret.json"
    outside.write_text(json.dumps({"findings": []}))
    monkeypatch.chdir(workdir)
    with pytest.raises(ValueError):
        diff_since_baseline({"crawl": str(outside), "baseline": {"expected_findings": []}})


def test_scan_route_run_payloads_refuses_without_policy_by_default(monkeypatch):
    class FakeResult:
        def to_dict(self):
            return {"target": "http://127.0.0.1:1", "pages": [], "findings": [], "js_endpoints": []}

    monkeypatch.setattr("shroodler.crawler.crawl_url", lambda *_a, **_k: FakeResult())
    monkeypatch.setattr("shroodler.validate.validate_crawl", lambda *_a, **_k: None)
    monkeypatch.setattr("shroodler_guardrails.policy.fetch_policy", lambda *_a, **_k: None)

    with pytest.raises(ValueError, match="require-policy|scan-policy|consent"):
        scan_route({"url": "http://127.0.0.1:1/", "run_payloads": True})


def test_check_idor_refuses_without_policy_by_default(monkeypatch):
    monkeypatch.setattr("shroodler_guardrails.policy.fetch_policy", lambda *_a, **_k: None)
    higher_doc = {"target": "http://127.0.0.1:1", "pages": []}
    with pytest.raises(ValueError, match="require-policy|scan-policy|consent"):
        check_idor({"higher_priv_crawl": higher_doc})


def test_check_idor_allow_without_policy_reaches_authz_diff(monkeypatch):
    monkeypatch.setattr("shroodler_guardrails.policy.fetch_policy", lambda *_a, **_k: None)
    called = {}

    def fake_authz_diff_run(doc, **kwargs):
        called["enforcer"] = kwargs.get("enforcer")
        return {"target": doc.get("target", ""), "findings": []}

    monkeypatch.setattr("shroodler.authz_diff.run", fake_authz_diff_run)
    higher_doc = {"target": "http://127.0.0.1:1", "pages": []}
    result = check_idor({"higher_priv_crawl": higher_doc, "allow_without_policy": True})
    assert result["findings"] == []
    assert called["enforcer"] is not None


def test_scan_route_headless_refuses_without_policy_by_default(monkeypatch):
    monkeypatch.setattr("shroodler_guardrails.policy.fetch_policy", lambda *_a, **_k: None)

    def fail_if_called(*_a, **_k):
        raise AssertionError("crawl_url should not run before the guardrail check")

    monkeypatch.setattr("shroodler.crawler.crawl_url", fail_if_called)

    with pytest.raises(ValueError, match="require-policy|scan-policy|consent"):
        scan_route({"url": "http://127.0.0.1:1/", "mode": "headless"})


def test_scan_route_headless_allow_without_policy_proceeds(monkeypatch):
    class FakeResult:
        def to_dict(self):
            return {"target": "http://127.0.0.1:1", "pages": [], "findings": [], "js_endpoints": []}

    monkeypatch.setattr("shroodler_guardrails.policy.fetch_policy", lambda *_a, **_k: None)
    monkeypatch.setattr("shroodler.crawler.crawl_url", lambda *_a, **_k: FakeResult())
    monkeypatch.setattr("shroodler.validate.validate_crawl", lambda *_a, **_k: None)

    doc = scan_route({"url": "http://127.0.0.1:1/", "mode": "headless", "allow_without_policy": True})
    assert doc["target"] == "http://127.0.0.1:1"


def test_scan_route_static_mode_does_not_require_policy(monkeypatch):
    class FakeResult:
        def to_dict(self):
            return {"target": "http://127.0.0.1:1", "pages": [], "findings": [], "js_endpoints": []}

    def fail_if_called(*_a, **_k):
        raise AssertionError("static mode should not need a policy fetch at all")

    monkeypatch.setattr("shroodler_guardrails.policy.fetch_policy", fail_if_called)
    monkeypatch.setattr("shroodler.crawler.crawl_url", lambda *_a, **_k: FakeResult())
    monkeypatch.setattr("shroodler.validate.validate_crawl", lambda *_a, **_k: None)

    doc = scan_route({"url": "http://127.0.0.1:1/"})
    assert doc["target"] == "http://127.0.0.1:1"


def test_check_idor_passes_through_identity_markers(monkeypatch):
    monkeypatch.setattr("shroodler_guardrails.policy.fetch_policy", lambda *_a, **_k: None)
    captured = {}

    def fake_authz_diff_run(doc, **kwargs):
        captured.update(kwargs)
        return {"target": doc.get("target", ""), "findings": []}

    monkeypatch.setattr("shroodler.authz_diff.run", fake_authz_diff_run)
    higher_doc = {"target": "http://127.0.0.1:1", "pages": []}
    check_idor(
        {
            "higher_priv_crawl": higher_doc,
            "allow_without_policy": True,
            "higher_priv_identity_markers": ["victim@example.com"],
            "lower_priv_identity_markers": ["me@example.com"],
            "require_identity_confirmation": True,
        }
    )
    assert captured["higher_priv_identity_markers"] == ["victim@example.com"]
    assert captured["lower_priv_identity_markers"] == ["me@example.com"]
    assert captured["require_identity_confirmation"] is True


def test_peer_write_requires_playbook_or_sessions():
    with pytest.raises(ValueError, match="playbook|from_sessions"):
        peer_write({})


def test_peer_write_refuses_without_policy_by_default(monkeypatch):
    monkeypatch.setattr("shroodler_guardrails.policy.fetch_policy", lambda *_a, **_k: None)
    with pytest.raises(ValueError, match="require-policy|scan-policy|consent"):
        peer_write({"playbook": {"target": "http://127.0.0.1:1", "writes": []}})


def test_peer_write_allow_without_policy_reaches_engine(monkeypatch):
    monkeypatch.setattr("shroodler_guardrails.policy.fetch_policy", lambda *_a, **_k: None)
    called = {}

    def fake_run(doc, **kwargs):
        called["enforcer"] = kwargs.get("enforcer")
        return {"target": doc.get("target", ""), "findings": [], "checked": []}

    monkeypatch.setattr("shroodler.peer_write.run", fake_run)
    result = peer_write(
        {"playbook": {"target": "http://127.0.0.1:1", "writes": []}, "allow_without_policy": True}
    )
    assert result["findings"] == []
    assert called["enforcer"] is not None


def test_extract_js_routes_requires_file():
    with pytest.raises(ValueError, match="file"):
        extract_js_routes({})


def test_extract_js_routes_reads_local_file(tmp_path, monkeypatch):
    monkeypatch.setenv("SHROODLER_MCP_ROOT", str(tmp_path))
    js = tmp_path / "app.js"
    js.write_text('const u = "/users/{userId}";', encoding="utf-8")
    out = extract_js_routes({"file": str(js)})
    assert out["routes"][0]["params"] == ["userId"]


def test_paced_fetch_requires_urls():
    with pytest.raises(ValueError, match="urls"):
        paced_fetch({})


def test_paced_fetch_refuses_without_policy_by_default(monkeypatch):
    monkeypatch.setattr("shroodler_guardrails.policy.fetch_policy", lambda *_a, **_k: None)
    with pytest.raises(ValueError, match="require-policy|scan-policy|consent"):
        paced_fetch({"urls": ["http://127.0.0.1:1/"]})


def test_paced_fetch_allow_without_policy_reaches_engine(monkeypatch):
    monkeypatch.setattr("shroodler_guardrails.policy.fetch_policy", lambda *_a, **_k: None)
    called = {}

    def fake_fetch(urls, **kwargs):
        called["enforcer"] = kwargs.get("enforcer")
        called["max_urls"] = kwargs.get("max_urls")
        return {"results": [{"url": urls[0], "status": 200}], "rate": 1}

    monkeypatch.setattr("shroodler.paced_fetch.fetch_urls", fake_fetch)
    result = paced_fetch({"urls": ["http://127.0.0.1:1/"], "allow_without_policy": True})
    assert result["results"][0]["status"] == 200
    assert called["enforcer"] is not None
    assert called["max_urls"] == 20


def test_project_root_uses_env_override(tmp_path, monkeypatch):
    monkeypatch.setenv("SHROODLER_MCP_ROOT", str(tmp_path))
    assert _project_root() == tmp_path.resolve()


def test_project_root_finds_git_ancestor(tmp_path, monkeypatch):
    monkeypatch.delenv("SHROODLER_MCP_ROOT", raising=False)
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    nested = repo / "a" / "b"
    nested.mkdir(parents=True)
    monkeypatch.chdir(nested)
    assert _project_root() == repo.resolve()


def test_reverify_fix_requires_url_and_finding_id():
    with pytest.raises(ValueError):
        reverify_fix({"url": "http://127.0.0.1:1/"})
    with pytest.raises(ValueError):
        reverify_fix({"finding_id": "missing-hsts"})


def test_reverify_fix_run_payloads_refuses_without_policy_by_default(monkeypatch):
    monkeypatch.setattr("shroodler_guardrails.policy.fetch_policy", lambda *_a, **_k: None)
    with pytest.raises(ValueError, match="require-policy|scan-policy|consent"):
        reverify_fix({"url": "http://127.0.0.1:1/", "finding_id": "missing-hsts"})


def test_reverify_fix_skips_guardrail_when_run_payloads_false(monkeypatch):
    called = {}

    def fake_reverify(url, finding_id, **kwargs):
        called.update(kwargs)
        return {"url": url, "finding_id": finding_id, "verified_fixed": True}

    monkeypatch.setattr("shroodler.reverify.reverify", fake_reverify)
    result = reverify_fix(
        {"url": "http://127.0.0.1:1/", "finding_id": "missing-hsts", "run_payloads": False}
    )
    assert result["verified_fixed"] is True
    assert called["enforcer"] is None


# ---------------------------------------------------------------------------
# check_ws_idor tests — use a local asyncio echo server so no network needed
# ---------------------------------------------------------------------------

def _make_tlcp_server(port: int, allowed_sub_ids: set):
    """Minimal Lightstreamer TLCP stub: accepts SUBOK for own sub_ids, REQERR for others."""
    import asyncio
    import threading
    import websockets.asyncio.server as ws_server

    async def handler(ws):
        async for raw in ws:
            msg = str(raw)
            if msg.strip() == "wsok":
                await ws.send("WSOK\r\n")
            elif msg.startswith("create_session"):
                await ws.send("CONOK,Stest,150000,10000,*\r\n")
            elif msg.startswith("control"):
                # parse LS_subId=N
                import re
                m = re.search(r"LS_subId=(\d+)", msg)
                sid = m.group(1) if m else "0"
                if int(sid) in allowed_sub_ids:
                    await ws.send(f"SUBOK,{sid},1,1\r\n")
                else:
                    await ws.send(f"REQERR,{sid},-2,SubscriptionNotAllowed\r\n")

    ready = threading.Event()
    loop = asyncio.new_event_loop()

    async def _serve():
        async with ws_server.serve(handler, "127.0.0.1", port):
            ready.set()
            await asyncio.Future()

    t = threading.Thread(target=lambda: loop.run_until_complete(_serve()), daemon=True)
    t.start()
    ready.wait(timeout=3)
    return t


def test_check_ws_idor_requires_ws_url():
    with pytest.raises(ValueError, match="ws_url"):
        check_ws_idor({})


def test_check_ws_idor_access_control_enforced():
    _make_tlcp_server(18765, allowed_sub_ids={1, 2})
    result = check_ws_idor({
        "ws_url": "ws://127.0.0.1:18765",
        "handshake_messages": ["wsok", "create_session\r\nLS_adapter_set=TEST"],
        "own_subscriptions": [
            {"id": "own-chan", "sub_id": 1, "message": "control\r\nLS_reqId=1&LS_op=add&LS_subId=1&LS_group=own"},
            {"id": "own-chan2", "sub_id": 2, "message": "control\r\nLS_reqId=2&LS_op=add&LS_subId=2&LS_group=own2"},
        ],
        "victim_subscriptions": [
            {"id": "victim-chan", "sub_id": 100, "message": "control\r\nLS_reqId=100&LS_op=add&LS_subId=100&LS_group=victim"},
        ],
        "collect_seconds": 2.0,
    })
    assert result["verdict"] == "access_control_enforced"
    assert result["severity"] == "none"
    assert result["own_baseline_ok"] is True
    assert result["victim_subscriptions"][0]["status"] == "denied"


def test_check_ws_idor_confirmed():
    _make_tlcp_server(18766, allowed_sub_ids={1, 200})  # victim sub 200 accidentally allowed
    result = check_ws_idor({
        "ws_url": "ws://127.0.0.1:18766",
        "handshake_messages": ["wsok", "create_session\r\nLS_adapter_set=TEST"],
        "own_subscriptions": [
            {"id": "own", "sub_id": 1, "message": "control\r\nLS_reqId=1&LS_op=add&LS_subId=1&LS_group=own"},
        ],
        "victim_subscriptions": [
            {"id": "victim", "sub_id": 200, "message": "control\r\nLS_reqId=200&LS_op=add&LS_subId=200&LS_group=victim"},
        ],
        "collect_seconds": 2.0,
    })
    assert result["verdict"] == "IDOR_CONFIRMED"
    assert result["severity"] == "high"
    assert result["victim_subscriptions"][0]["status"] == "allowed"
