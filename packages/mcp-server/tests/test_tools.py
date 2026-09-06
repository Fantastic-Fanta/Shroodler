from __future__ import annotations

import pytest
from shroodler_mcp.tools import (
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
