from __future__ import annotations

import pytest

from shroodler.ask import answer


def _finding(id_, severity, category, url="http://x/a"):
    return {
        "id": id_,
        "severity": severity,
        "category": category,
        "url": url,
        "description": "d",
        "evidence": None,
    }


@pytest.fixture
def scan():
    return {
        "target": "http://x",
        "findings": [
            _finding("missing-hsts", "medium", "header"),
            _finding("secret-aws-key", "critical", "secret"),
            _finding("authz-still-accessible", "medium", "auth"),
        ],
    }


def test_summary(scan):
    result = answer("summarize the findings", scan)
    assert result.intent == "summary"
    assert result.data["total"] == 3


def test_severity_exact(scan):
    result = answer("show critical findings", scan)
    assert result.intent == "severity-exact"
    assert len(result.data["findings"]) == 1
    assert result.data["findings"][0]["id"] == "secret-aws-key"


def test_severity_or_higher(scan):
    result = answer("show medium or higher findings", scan)
    assert result.intent == "severity-at-or-above"
    assert len(result.data["findings"]) == 3


def test_category(scan):
    result = answer("any secret issues?", scan)
    assert result.intent == "category"
    assert len(result.data["findings"]) == 1


def test_reachable_without_auth(scan):
    result = answer("what's reachable without auth", scan)
    assert result.intent == "reachable-without-auth"
    assert len(result.data["findings"]) == 1
    assert result.data["findings"][0]["id"] == "authz-still-accessible"


def test_new_since(scan):
    older = {"target": "http://x", "findings": [_finding("missing-hsts", "medium", "header")]}
    result = answer("what's new since last scan", scan, older_scan=older)
    assert result.intent == "new-since"
    ids = {f["id"] for f in result.data["introduced"]}
    assert ids == {"secret-aws-key", "authz-still-accessible"}


def test_resolved_since(scan):
    older = {
        "target": "http://x",
        "findings": [
            _finding("missing-hsts", "medium", "header"),
            _finding("gone", "low", "header"),
        ],
    }
    result = answer("what got resolved", scan, older_scan=older)
    assert result.intent == "resolved-since"
    assert result.data["resolved"] == [{"id": "gone", "url": "http://x/a"}]


def test_unrecognized(scan):
    result = answer("blah blah nonsense", scan)
    assert result.intent == "unrecognized"


def test_external_backend(monkeypatch, scan, tmp_path):
    script = tmp_path / "fake_llm.sh"
    script.write_text("#!/bin/sh\necho \"external says: $1\"\n")
    script.chmod(0o755)
    monkeypatch.setenv("SHROODLER_ASK_LLM_CMD", str(script))
    result = answer("anything", scan)
    assert result.answered_by == "external"
    assert "external says: anything" in result.text
