from __future__ import annotations

import json

import pytest
from shroodler_mcp.tools import (
    _project_root,
    _resolve_safe_path,
    check_idor,
    diff_since_baseline,
    explain_finding,
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
