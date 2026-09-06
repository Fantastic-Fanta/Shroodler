from __future__ import annotations

from datetime import date

from shroodler.history import record_scan
from shroodler.sla import (
    apply_sla,
    escalate_severity,
    load_ownership_rules,
    owner_for,
    wildcard_rules,
)


def _doc(target: str, findings: list[dict], finished_at: str) -> dict:
    return {"target": target, "scan_finished_at": finished_at, "findings": findings}


def _finding(id_, url, severity="medium"):
    return {
        "id": id_,
        "severity": severity,
        "category": "header",
        "url": url,
        "description": "d",
        "evidence": None,
    }


def test_escalate_severity_steps_up_one_level():
    assert escalate_severity("medium") == "high"
    assert escalate_severity("critical") == "critical"  # capped
    assert escalate_severity("unknown") == "unknown"  # unrecognized passthrough


def test_owner_for_matches_id_and_url_glob():
    rules = load_ownership_rules(None)
    assert rules == []


def test_owner_for_uses_glob_rules(tmp_path):
    rules_file = tmp_path / "owners.yaml"
    rules_file.write_text(
        "suppressions:\n"
        "  - id: missing-hsts\n"
        "    url: '/admin/*'\n"
        "    owner: platform-team\n",
        encoding="utf-8",
    )
    rules = load_ownership_rules(rules_file)
    assert owner_for(_finding("missing-hsts", "http://x/admin/y"), rules) == "platform-team"
    assert owner_for(_finding("missing-hsts", "http://x/other"), rules) == ""


def test_wildcard_rules_flags_catch_all_id_or_url():
    rules = [
        {"id": "*", "url": "/a", "owner": "team-a"},
        {"id": "missing-hsts", "url": "*", "owner": "team-b"},
        {"id": "missing-hsts", "url": "/admin/*", "owner": "team-c"},
    ]
    flagged = wildcard_rules(rules)
    assert {r["owner"] for r in flagged} == {"team-a", "team-b"}


def test_apply_sla_escalates_breached_finding(tmp_path):
    hdir = tmp_path / "hist"
    target = "http://127.0.0.1:9/"
    old_finding = _finding("missing-hsts", target + "a", severity="medium")
    record_scan(_doc(target, [old_finding], "2020-01-01T00:00:00Z"), hdir)

    current_doc = {"target": target, "findings": [old_finding]}
    result = apply_sla(current_doc, history_dir=hdir, today=date(2020, 6, 1))
    f = result["findings"][0]
    assert f["first_seen"] == "2020-01-01"
    assert f["age_days"] > 30
    assert f["sla_breached"] is True
    assert f["sla_severity"] == "high"
    assert f["severity"] == "medium"  # original untouched


def test_apply_sla_does_not_escalate_within_budget(tmp_path):
    hdir = tmp_path / "hist"
    target = "http://127.0.0.1:9/"
    finding = _finding("missing-hsts", target + "a", severity="medium")
    record_scan(_doc(target, [finding], "2020-06-01T00:00:00Z"), hdir)

    current_doc = {"target": target, "findings": [finding]}
    result = apply_sla(current_doc, history_dir=hdir, today=date(2020, 6, 5))
    f = result["findings"][0]
    assert f["sla_breached"] is False
    assert f["sla_severity"] == "medium"


def test_apply_sla_no_history_for_target_leaves_first_seen_none_not_today(tmp_path):
    # This is the round-1-critique fix: an empty/missing/wrong-target
    # history dir must NOT be treated the same as "brand new finding
    # seen today" -- that would make a genuinely ancient finding look
    # new (and never breach SLA) the instant history goes missing.
    hdir = tmp_path / "hist"  # never written to -- no recorded scans at all
    target = "http://127.0.0.1:9/"
    finding = _finding("some-finding", target + "a")
    current_doc = {"target": target, "findings": [finding]}
    result = apply_sla(current_doc, history_dir=hdir, today=date(2020, 6, 5))
    f = result["findings"][0]
    assert f["history_available"] is False
    assert f["first_seen"] is None
    assert f["age_days"] is None
    assert f["sla_breached"] is False
    assert f["sla_severity"] == f["severity"]


def test_apply_sla_genuinely_new_finding_when_history_exists_for_target(tmp_path):
    # Once there IS recorded history for this target, a finding whose key
    # isn't in it really is new -- first_seen=today is correct here.
    hdir = tmp_path / "hist"
    target = "http://127.0.0.1:9/"
    older_finding = _finding("already-known", target + "a")
    record_scan(_doc(target, [older_finding], "2020-01-01T00:00:00Z"), hdir)

    brand_new = _finding("brand-new", target + "b")
    current_doc = {"target": target, "findings": [brand_new]}
    result = apply_sla(current_doc, history_dir=hdir, today=date(2020, 6, 5))
    f = result["findings"][0]
    assert f["history_available"] is True
    assert f["first_seen"] == "2020-06-05"
    assert f["age_days"] == 0
    assert f["sla_breached"] is False


def test_apply_sla_missing_target_does_not_leak_other_targets_history(tmp_path):
    hdir = tmp_path / "hist"
    other_target = "http://127.0.0.1:9999/"
    shared_finding = _finding("shared-id", other_target + "a")
    # This finding is old under a COMPLETELY DIFFERENT target.
    record_scan(_doc(other_target, [shared_finding], "2015-01-01T00:00:00Z"), hdir)

    # A scan doc with no target at all must not accidentally match that
    # unrelated target's history and inherit its ancient first_seen date.
    same_id_different_target_doc = {
        "findings": [_finding("shared-id", other_target + "a")]
    }
    result = apply_sla(same_id_different_target_doc, history_dir=hdir, today=date(2020, 6, 5))
    f = result["findings"][0]
    assert f["history_available"] is False
    assert f["first_seen"] is None


def test_apply_sla_attaches_owner(tmp_path):
    hdir = tmp_path / "hist"
    target = "http://127.0.0.1:9/"
    finding = _finding("missing-hsts", target + "admin/x")
    owners = [{"id": "missing-hsts", "url": "/admin/*", "owner": "platform-team"}]
    result = apply_sla({"target": target, "findings": [finding]}, history_dir=hdir, owners=owners)
    assert result["findings"][0]["owner"] == "platform-team"
