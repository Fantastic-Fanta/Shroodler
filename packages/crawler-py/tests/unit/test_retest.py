from __future__ import annotations

from shroodler.retest import (
    RetestReport,
    classify_reverify,
    latest_report,
    load_history,
    retest_findings,
    save_report,
    targets_from_doc,
)

# --- classify_reverify: the three states -----------------------------------


def test_classify_reproduces_when_still_present():
    status, _ = classify_reverify({"still_present": True, "verified_fixed": False})
    assert status == "reproduces"


def test_classify_fixed_only_on_clean_rescan():
    status, _ = classify_reverify(
        {"still_present": False, "verified_fixed": True, "warnings": []}
    )
    assert status == "fixed"


def test_classify_unconfirmable_when_warnings_present():
    # reverify warns when it could not re-fuzz the original parameter: a
    # verified_fixed under that warning is not trustworthy.
    status, reason = classify_reverify(
        {
            "still_present": False,
            "verified_fixed": True,
            "warnings": ["url has no query string -- ..."],
        }
    )
    assert status == "unconfirmable"
    assert "query string" in reason


def test_classify_unconfirmable_on_guardrail():
    status, _ = classify_reverify(
        {"still_present": False, "verified_fixed": True, "guardrail": {"blocked": 3}}
    )
    assert status == "unconfirmable"


def test_classify_unconfirmable_on_error():
    status, reason = classify_reverify({"error": "connection refused"})
    assert status == "unconfirmable"
    assert "connection refused" in reason


# --- targets_from_doc ------------------------------------------------------


def test_targets_from_doc_confirmed_only_and_deduped():
    doc = {
        "findings": [
            {"id": "sqli", "url": "http://t/a", "confidence": "confirmed"},
            {"id": "sqli", "url": "http://t/a", "confidence": "confirmed"},  # dup
            {"id": "xss", "url": "http://t/b", "confidence": "heuristic"},  # dropped
        ]
    }
    assert targets_from_doc(doc) == [("http://t/a", "sqli")]
    assert ("http://t/b", "xss") in targets_from_doc(doc, confirmed_only=False)


# --- retest_findings: tracking + transitions -------------------------------


def _fake_reverify(results):
    """Return a reverify stub that looks up its answer by (url, finding_id)."""

    def _fn(url, finding_id, **kw):
        return results[(url, finding_id)]

    return _fn


def test_retest_builds_report_with_counts():
    results = {
        ("http://t/a", "sqli"): {"still_present": True},
        ("http://t/b", "xss"): {"still_present": False, "verified_fixed": True, "warnings": []},
    }
    report = retest_findings(
        [("http://t/a", "sqli"), ("http://t/b", "xss")],
        reverify_fn=_fake_reverify(results),
    )
    assert report.counts == {"reproduces": 1, "fixed": 1, "unconfirmable": 0}


def test_retest_flags_regression_against_prior():
    prior = RetestReport(
        entries=[{"url": "http://t/a", "finding_id": "sqli", "status": "fixed"}]
    )
    results = {("http://t/a", "sqli"): {"still_present": True}}
    report = retest_findings(
        [("http://t/a", "sqli")], reverify_fn=_fake_reverify(results), prior=prior
    )
    assert report.entries[0].transition == "regressed"
    assert report.entries[0].prior_status == "fixed"
    assert len(report.regressions) == 1


def test_retest_newly_fixed_transition():
    prior = RetestReport(
        entries=[{"url": "http://t/a", "finding_id": "sqli", "status": "reproduces"}]
    )
    results = {("http://t/a", "sqli"): {"still_present": False, "verified_fixed": True}}
    report = retest_findings(
        [("http://t/a", "sqli")], reverify_fn=_fake_reverify(results), prior=prior
    )
    assert report.entries[0].transition == "newly_fixed"
    assert not report.regressions


def test_retest_exception_is_unconfirmable_not_fatal():
    def _boom(url, finding_id, **kw):
        raise RuntimeError("go engine down")

    report = retest_findings([("http://t/a", "sqli")], reverify_fn=_boom)
    assert report.entries[0].status == "unconfirmable"
    assert "go engine down" in report.entries[0].reason


# --- persistence -----------------------------------------------------------


def test_save_and_load_history_roundtrip(tmp_path):
    path = tmp_path / "hist" / "retest.jsonl"
    results = {("http://t/a", "sqli"): {"still_present": True}}
    r1 = retest_findings([("http://t/a", "sqli")], reverify_fn=_fake_reverify(results))
    save_report(r1, path)
    results2 = {("http://t/a", "sqli"): {"still_present": False, "verified_fixed": True}}
    r2 = retest_findings([("http://t/a", "sqli")], reverify_fn=_fake_reverify(results2))
    save_report(r2, path)

    history = load_history(path)
    assert len(history) == 2
    assert history[0].entries[0].status == "reproduces"
    assert latest_report(path).entries[0].status == "fixed"


def test_load_history_missing_file_is_empty(tmp_path):
    assert load_history(tmp_path / "nope.jsonl") == []
    assert latest_report(tmp_path / "nope.jsonl") is None


# --- CLI command (cmd_retest) ----------------------------------------------

import json  # noqa: E402
from types import SimpleNamespace  # noqa: E402

from shroodler.cli import cmd_retest  # noqa: E402


def _retest_args(scan_path, **over):
    base = dict(
        scan=str(scan_path),
        all=False,
        mode="static",
        allow_external=False,
        no_payloads=True,
        history=None,
        output=None,
        require_policy=False,
        policy_file=None,
        audit_log=None,
    )
    base.update(over)
    return SimpleNamespace(**base)


def test_cmd_retest_tracks_and_flags_regression(tmp_path, monkeypatch, capsys):
    scan = tmp_path / "scan.json"
    scan.write_text(
        json.dumps(
            {
                "target": "http://t/",
                "findings": [
                    {"id": "sqli", "url": "http://t/a", "confidence": "confirmed"}
                ],
            }
        ),
        encoding="utf-8",
    )
    history = tmp_path / "retest.jsonl"

    # First run: fixed.
    monkeypatch.setattr(
        "shroodler.reverify.reverify",
        lambda url, fid, **kw: {"still_present": False, "verified_fixed": True, "warnings": []},
    )
    assert cmd_retest(_retest_args(scan, history=str(history))) == 0

    # Second run: it reproduces again -> regression -> non-zero exit.
    monkeypatch.setattr(
        "shroodler.reverify.reverify",
        lambda url, fid, **kw: {"still_present": True},
    )
    rc = cmd_retest(_retest_args(scan, history=str(history)))
    assert rc == 1
    err = capsys.readouterr().err
    assert "REGRESSION" in err
    assert len(load_history(history)) == 2
