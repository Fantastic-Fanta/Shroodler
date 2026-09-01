from __future__ import annotations

import argparse
import json
from pathlib import Path
from xml.etree import ElementTree

from shroodler.baseline import document_to_baseline
from shroodler.cli import cmd_baseline, cmd_diff, cmd_report
from shroodler.diffcmd import diff_documents, diff_outcome
from shroodler.suppress import filter_findings, glob_match, parse_suppressions

DOC = {
    "target": "http://127.0.0.1:8081",
    "crawler": {"name": "shroodler-py", "version": "0.1.0", "mode": "static"},
    "pages": [
        {
            "url": "http://127.0.0.1:8081/",
            "status_code": 200,
            "forms": [],
            "params": [],
            "cookies": [],
            "headers": {"present": [], "missing": []},
            "js_files": [],
        },
        {
            "url": "http://127.0.0.1:8081/login",
            "status_code": 200,
            "forms": [
                {
                    "action": "/login",
                    "method": "POST",
                    "fields": [
                        {"name": "username", "type": "text", "hidden": False},
                        {"name": "password", "type": "password", "hidden": False},
                    ],
                }
            ],
            "params": [],
            "cookies": [],
            "headers": {"present": [], "missing": []},
            "js_files": [],
        },
    ],
    "findings": [
        {
            "id": "missing-csp",
            "severity": "medium",
            "category": "header",
            "url": "http://127.0.0.1:8081/login",
            "description": "CSP missing",
            "evidence": None,
        },
        {
            "id": "server-version-leak",
            "severity": "info",
            "category": "header",
            "url": "http://127.0.0.1:8081/",
            "description": "Server header",
            "evidence": None,
        },
    ],
}


def test_glob_match_star_crosses_slashes():
    assert glob_match("/static/*", "/static/app.js")
    assert glob_match("*", "/login")
    assert not glob_match("/login", "/settings")


def test_baseline_from_scan_is_stable():
    base = document_to_baseline(DOC, name="lab-app")
    assert base["target_app"] == "lab-app"
    assert base["expected_pages"] == ["/", "/login"]
    assert base["expected_forms"]["/login"] == ["password", "username"]
    assert base["expected_findings"] == [
        {"id": "missing-csp", "url": "/login"},
        {"id": "server-version-leak", "url": "/"},
    ]
    assert diff_documents(DOC, base) == []


def test_baseline_omits_suppressions():
    rules = parse_suppressions(
        "suppressions:\n  - id: server-version-leak\n    url: '*'\n    reason: noise\n"
    )
    base = document_to_baseline(DOC, name="lab-app", suppressions=rules)
    ids = {f["id"] for f in base["expected_findings"]}
    assert ids == {"missing-csp"}
    assert "server-version-leak" not in ids


def test_gate_fails_on_new_not_resolved():
    base = document_to_baseline(DOC, name="lab-app")
    extra = json.loads(json.dumps(DOC))
    extra["findings"].append(
        {
            "id": "exposed-file",
            "severity": "high",
            "category": "exposed-file",
            "url": "http://127.0.0.1:8081/.env",
            "description": "env",
            "evidence": None,
        }
    )
    extra["pages"].append(
        {
            "url": "http://127.0.0.1:8081/.env",
            "status_code": 200,
            "forms": [],
            "params": [],
            "cookies": [],
            "headers": {"present": [], "missing": []},
            "js_files": [],
        }
    )
    errors = diff_documents(extra, base, gate=True)
    assert any("new finding exposed-file" in e for e in errors)

    gone = json.loads(json.dumps(DOC))
    gone["findings"] = [f for f in gone["findings"] if f["id"] != "missing-csp"]
    outcome = diff_outcome(gone, base, gate=True)
    assert outcome.errors == []
    assert any("resolved missing-csp" in r for r in outcome.resolved)
    assert diff_documents(gone, base)  # fixture mode still fails


def test_gate_respects_suppressions():
    base = document_to_baseline(DOC, name="lab-app")
    extra = json.loads(json.dumps(DOC))
    extra["findings"].append(
        {
            "id": "missing-csp",
            "severity": "medium",
            "category": "header",
            "url": "http://127.0.0.1:8081/static/x.js",
            "description": "csp",
            "evidence": None,
        }
    )
    rules = parse_suppressions(
        "suppressions:\n  - id: missing-csp\n    url: /static/*\n    reason: assets\n"
    )
    assert diff_documents(extra, base, gate=True, suppressions=rules) == []
    assert diff_documents(extra, base, gate=True)
    assert len(filter_findings(extra["findings"], rules)) == 2


def test_cmd_baseline_and_gate_cli(tmp_path):
    scan = tmp_path / "scan.json"
    scan.write_text(json.dumps(DOC), encoding="utf-8")
    out = tmp_path / "expected_findings.json"
    ns = argparse.Namespace(findings=str(scan), output=str(out), name="cli-app", suppressions=None)
    assert cmd_baseline(ns) == 0
    body = json.loads(out.read_text(encoding="utf-8"))
    assert body["target_app"] == "cli-app"
    ns = argparse.Namespace(
        findings=str(scan),
        expected=str(out),
        pages_only=False,
    )
    assert cmd_diff(ns) == 0


def test_cmd_report_sarif_junit(tmp_path):
    scan = tmp_path / "scan.json"
    scan.write_text(json.dumps(DOC), encoding="utf-8")
    sarif_path = tmp_path / "r.sarif"
    ns = argparse.Namespace(
        findings=str(scan),
        format="sarif",
        output=str(sarif_path),
        suppressions=None,
    )
    assert cmd_report(ns) == 0
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["ruleId"] in {"missing-csp", "server-version-leak"}
    junit_path = tmp_path / "r.xml"
    ns = argparse.Namespace(
        findings=str(scan),
        format="junit",
        output=str(junit_path),
        suppressions=None,
    )
    assert cmd_report(ns) == 0
    tree = ElementTree.parse(junit_path)
    assert tree.getroot().tag == "testsuite"
    assert int(tree.getroot().attrib["failures"]) == 2


def test_expected_generator_round_trip(tmp_path):
    from shroodler.cli import build_parser

    fixture = Path(__file__).resolve().parent.parent / "fixtures" / "scan_min.json"
    scan = json.loads(fixture.read_text(encoding="utf-8"))
    out = tmp_path / "expected_findings.json"
    parser = build_parser()
    ns = parser.parse_args(["expected", str(fixture), "--output", str(out), "--name", "app1"])
    assert ns.func is cmd_baseline
    assert ns.func(ns) == 0
    body = json.loads(out.read_text(encoding="utf-8"))
    assert body["target_app"] == "app1"
    assert body["expected_pages"] == ["/login"]
    assert body["expected_forms"]["/login"] == ["password", "username"]
    assert body["expected_findings"] == [{"id": "missing-csp", "url": "/login"}]
    assert body["expected_not_found"] == []
    assert diff_documents(scan, body) == []
