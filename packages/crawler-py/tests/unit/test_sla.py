from __future__ import annotations

from datetime import date

from shroodler.history import record_scan
from shroodler.sla import apply_sla, escalate_severity, load_ownership_rules, owner_for


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


def test_apply_sla_new_finding_defaults_first_seen_to_today(tmp_path):
    hdir = tmp_path / "hist"
    target = "http://127.0.0.1:9/"
    finding = _finding("brand-new", target + "a")
    current_doc = {"target": target, "findings": [finding]}
    result = apply_sla(current_doc, history_dir=hdir, today=date(2020, 6, 5))
    f = result["findings"][0]
    assert f["first_seen"] == "2020-06-05"
    assert f["age_days"] == 0
    assert f["sla_breached"] is False


def test_apply_sla_attaches_owner(tmp_path):
    hdir = tmp_path / "hist"
    target = "http://127.0.0.1:9/"
    finding = _finding("missing-hsts", target + "admin/x")
    owners = [{"id": "missing-hsts", "url": "/admin/*", "owner": "platform-team"}]
    result = apply_sla({"target": target, "findings": [finding]}, history_dir=hdir, owners=owners)
    assert result["findings"][0]["owner"] == "platform-team"
