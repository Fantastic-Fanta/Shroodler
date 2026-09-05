from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from run_parity import compare, finding_set  # noqa: E402


def _doc(findings: list[dict]) -> dict:
    return {"pages": [], "findings": findings}


def test_finding_set_includes_severity():
    doc = _doc([{"id": "missing-csp", "url": "http://x/", "severity": "medium"}])
    assert finding_set(doc) == {("missing-csp", "/", "medium")}


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
