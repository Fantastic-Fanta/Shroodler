from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from run_parity import compare, finding_set


def _doc(findings: list[dict]) -> dict:
    return {"pages": [], "findings": findings}


def test_finding_set_includes_severity():
    doc = _doc([{"id": "missing-csp", "url": "http://x/", "severity": "medium"}])
    assert finding_set(doc) == {("missing-csp", "/", "", "medium")}


def test_finding_set_includes_query_string():
    # A purely query-string-driven check (e.g. the OAuth checks) has its
    # entire signal in the query -- two findings differing only by query
    # must not collapse to the same key.
    doc = _doc(
        [
            {"id": "oauth-missing-state", "url": "http://x/authorize?a=1", "severity": "medium"},
            {"id": "oauth-missing-state", "url": "http://x/authorize?a=2", "severity": "medium"},
        ]
    )
    assert finding_set(doc) == {
        ("oauth-missing-state", "/authorize", "a=1", "medium"),
        ("oauth-missing-state", "/authorize", "a=2", "medium"),
    }


def test_compare_flags_severity_regression_even_when_id_and_path_match():
    # A finding whose id/path match across engines but whose severity
    # differs (e.g. one engine silently downgraded a real vulnerability to
    # "info") must NOT be reported as parity-ok.
    py_doc = _doc([{"id": "exposed-file", "url": "http://x/.git/HEAD", "severity": "high"}])
    go_doc = _doc([{"id": "exposed-file", "url": "http://x/.git/HEAD", "severity": "info"}])
    errs = compare(py_doc, go_doc)
    assert errs, "expected a severity mismatch to be reported"
    assert "finding mismatch" in errs[0]


def test_compare_ok_when_id_path_and_severity_all_match():
    py_doc = _doc([{"id": "exposed-file", "url": "http://x/.git/HEAD", "severity": "high"}])
    go_doc = _doc([{"id": "exposed-file", "url": "http://x/.git/HEAD", "severity": "high"}])
    assert compare(py_doc, go_doc) == []


def test_python_only_finding_id_excluded_from_comparison():
    doc = {
        "id": "csrf-state-change-unprotected",
        "url": "http://x/edit",
        "severity": "medium",
        "category": "auth",
    }
    assert finding_set(_doc([doc])) == set()
    assert compare(_doc([doc]), _doc([])) == []


def test_python_only_category_excluded_from_comparison():
    # sri-missing/mixed-content (category "subresource") run unconditionally
    # in crawler-py but have no Go implementation yet -- a Python-only
    # crawl must not be reported as a parity mismatch just because
    # shroodler-go never emits this category at all.
    doc = {
        "id": "sri-missing",
        "url": "http://x/",
        "severity": "low",
        "category": "subresource",
    }
    assert finding_set(_doc([doc])) == set()
    py_doc = _doc([doc])
    go_doc = _doc([])
    assert compare(py_doc, go_doc) == []


def test_go_emitting_a_python_only_category_fails_loudly():
    # If shroodler-go ever starts emitting something tagged with a
    # category this script assumes is Python-only, that must fail the
    # gate instead of silently staying unchecked -- see the
    # PYTHON_ONLY_CATEGORIES comment.
    py_doc = _doc([])
    go_doc = _doc(
        [{"id": "sri-missing", "url": "http://x/", "severity": "low", "category": "subresource"}]
    )
    errs = compare(py_doc, go_doc)
    assert any("Python-only" in e for e in errs)
