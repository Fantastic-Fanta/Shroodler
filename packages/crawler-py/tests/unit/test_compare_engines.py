from __future__ import annotations

from shroodler.compare_engines import merge_engine_results


def _finding(id_, url, severity="medium"):
    return {
        "id": id_,
        "severity": severity,
        "category": "header",
        "url": url,
        "description": "d",
        "evidence": None,
    }


def test_finding_in_both_engines_is_marked_agreed():
    py_doc = {"target": "http://x", "pages": [], "findings": [_finding("missing-hsts", "http://x/a")]}
    go_doc = {"target": "http://x", "pages": [], "findings": [_finding("missing-hsts", "http://x/a")]}
    merged = merge_engine_results(py_doc, go_doc)
    assert len(merged["findings"]) == 1
    assert set(merged["findings"][0]["engines"]) == {"python", "go"}
    assert merged["engine_agreement"] == {
        "agreed": 1,
        "only_python": 0,
        "only_go": 0,
        "total_distinct": 1,
    }


def test_finding_only_in_python_is_marked_accordingly():
    py_doc = {"target": "http://x", "pages": [], "findings": [_finding("sri-missing", "http://x/a")]}
    go_doc = {"target": "http://x", "pages": [], "findings": []}
    merged = merge_engine_results(py_doc, go_doc)
    assert merged["findings"][0]["engines"] == ["python"]
    assert merged["engine_agreement"]["only_python"] == 1
    assert merged["engine_agreement"]["only_go"] == 0


def test_severity_disagreement_is_flagged():
    py_doc = {
        "target": "http://x",
        "pages": [],
        "findings": [_finding("missing-hsts", "http://x/a", severity="high")],
    }
    go_doc = {
        "target": "http://x",
        "pages": [],
        "findings": [_finding("missing-hsts", "http://x/a", severity="medium")],
    }
    merged = merge_engine_results(py_doc, go_doc)
    disagreement = merged["findings"][0]["severity_disagreement"]
    assert disagreement == {"python": ["high"], "go": ["medium"]}


def test_same_engine_duplicate_severities_are_not_reported_as_cross_engine_disagreement():
    # Two Set-Cookie headers on one page can both trip insecure-cookie
    # with different severities under ONE engine -- this must never be
    # mislabeled as "the Go engine disagrees" when Go found nothing.
    py_doc = {
        "target": "http://x",
        "pages": [],
        "findings": [
            _finding("insecure-cookie", "http://x/a", severity="high"),
            _finding("insecure-cookie", "http://x/a", severity="medium"),
        ],
    }
    go_doc = {"target": "http://x", "pages": [], "findings": []}
    merged = merge_engine_results(py_doc, go_doc)
    assert len(merged["findings"]) == 1
    assert merged["findings"][0]["engines"] == ["python"]
    assert "severity_disagreement" not in merged["findings"][0]


def test_real_cross_engine_disagreement_with_same_engine_duplicates_present():
    py_doc = {
        "target": "http://x",
        "pages": [],
        "findings": [
            _finding("insecure-cookie", "http://x/a", severity="high"),
            _finding("insecure-cookie", "http://x/a", severity="medium"),
        ],
    }
    go_doc = {
        "target": "http://x",
        "pages": [],
        "findings": [_finding("insecure-cookie", "http://x/a", severity="low")],
    }
    merged = merge_engine_results(py_doc, go_doc)
    disagreement = merged["findings"][0]["severity_disagreement"]
    assert disagreement == {"python": ["high", "medium"], "go": ["low"]}


def test_query_string_distinguishes_findings():
    py_doc = {
        "target": "http://x",
        "pages": [],
        "findings": [_finding("oauth-missing-state", "http://x/authorize?response_type=code")],
    }
    go_doc = {
        "target": "http://x",
        "pages": [],
        "findings": [_finding("oauth-missing-state", "http://x/authorize?response_type=token")],
    }
    merged = merge_engine_results(py_doc, go_doc)
    assert len(merged["findings"]) == 2
    assert merged["engine_agreement"]["agreed"] == 0
