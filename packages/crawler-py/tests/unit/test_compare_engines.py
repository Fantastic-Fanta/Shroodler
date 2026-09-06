from __future__ import annotations

import pytest

from shroodler.compare_engines import EngineOrderError, merge_engine_results


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
        "engine_verification": "unverified",
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


def test_swapped_argument_order_is_rejected():
    py_doc = {"target": "http://x", "crawler": {"name": "shroodler-py"}, "findings": []}
    go_doc = {"target": "http://x", "crawler": {"name": "shroodler-go"}, "findings": []}
    # Called in the wrong order: go_doc first, py_doc second.
    with pytest.raises(EngineOrderError):
        merge_engine_results(go_doc, py_doc)


def test_correct_argument_order_is_accepted():
    py_doc = {"target": "http://x", "crawler": {"name": "shroodler-py"}, "findings": []}
    go_doc = {"target": "http://x", "crawler": {"name": "shroodler-go"}, "findings": []}
    merge_engine_results(py_doc, go_doc)  # no raise


def test_missing_crawler_metadata_does_not_block_merge():
    py_doc = {"target": "http://x", "findings": []}
    go_doc = {"target": "http://x", "findings": []}
    merged = merge_engine_results(py_doc, go_doc)  # no raise -- unknown engine name isn't an error
    # ...but it's not silently treated as verified either.
    assert merged["engine_agreement"]["engine_verification"] == "unverified"


def test_correct_names_are_marked_verified():
    py_doc = {"target": "http://x", "crawler": {"name": "shroodler-py"}, "findings": []}
    go_doc = {"target": "http://x", "crawler": {"name": "shroodler-go"}, "findings": []}
    merged = merge_engine_results(py_doc, go_doc)
    assert merged["engine_agreement"]["engine_verification"] == "verified"


def test_substring_evasion_of_the_old_heuristic_is_no_longer_possible():
    # A name like "shroodler-go-copy" contains "py" (via "co-py") and
    # "go" both -- a naive substring check on either side could miss a
    # real swap. Exact-name comparison against the canonical opposite
    # name has no such gap: this name isn't literally "shroodler-go" or
    # "shroodler-py", so it's correctly treated as unrecognized (not
    # silently trusted as either engine) rather than falsely cleared.
    py_doc = {"target": "http://x", "crawler": {"name": "shroodler-go-copy"}, "findings": []}
    go_doc = {"target": "http://x", "crawler": {"name": "shroodler-go"}, "findings": []}
    merged = merge_engine_results(py_doc, go_doc)  # not literally "shroodler-go" -> no raise
    assert merged["engine_agreement"]["engine_verification"] == "unverified"

    # But an ACTUAL swap using the exact canonical names is still caught.
    swapped_py = {"target": "http://x", "crawler": {"name": "shroodler-go"}, "findings": []}
    swapped_go = {"target": "http://x", "crawler": {"name": "shroodler-py"}, "findings": []}
    with pytest.raises(EngineOrderError):
        merge_engine_results(swapped_py, swapped_go)
