from __future__ import annotations

from shroodler.attack_path import build_attack_path, render_attack_path_markdown


def _finding(id_, url, severity="medium", category="header"):
    return {
        "id": id_,
        "severity": severity,
        "category": category,
        "url": url,
        "description": "d",
        "evidence": None,
    }


def test_path_depth_computed_from_url():
    doc = {
        "target": "http://x",
        "findings": [_finding("missing-hsts", "http://x/a/b/c")],
    }
    report = build_attack_path(doc)
    assert report["nodes"][0]["path_depth"] == 3


def test_homepage_finding_has_zero_depth():
    doc = {"target": "http://x", "findings": [_finding("missing-hsts", "http://x/")]}
    report = build_attack_path(doc)
    assert report["nodes"][0]["path_depth"] == 0


def test_weak_token_excluded_as_its_own_node_but_tracked():
    doc = {
        "target": "http://x",
        "findings": [
            _finding("reset-token-sequential", "http://x/reset", category="auth"),
            _finding("authz-still-accessible", "http://x/account", category="auth"),
        ],
    }
    report = build_attack_path(doc)
    assert report["weak_tokens_found"] == ["reset-token-sequential"]
    ids = [n["id"] for n in report["nodes"]]
    assert "reset-token-sequential" not in ids
    assert "authz-still-accessible" in ids


def test_auth_category_finding_gets_token_context_note_when_weak_token_present():
    doc = {
        "target": "http://x",
        "findings": [
            _finding("reset-token-short", "http://x/reset", category="auth"),
            _finding("authz-still-accessible", "http://x/account", category="auth"),
        ],
    }
    report = build_attack_path(doc)
    node = next(n for n in report["nodes"] if n["id"] == "authz-still-accessible")
    assert node["relevant_token_context"] is True
    assert "guessable session/reset token" in node["narrative"]


def test_non_auth_finding_not_flagged_even_with_weak_token_present():
    doc = {
        "target": "http://x",
        "findings": [
            _finding("reset-token-short", "http://x/reset", category="auth"),
            _finding("missing-hsts", "http://x/a", category="header"),
        ],
    }
    report = build_attack_path(doc)
    node = next(n for n in report["nodes"] if n["id"] == "missing-hsts")
    assert node["relevant_token_context"] is False


def test_nodes_sorted_by_depth_then_severity():
    doc = {
        "target": "http://x",
        "findings": [
            _finding("a", "http://x/deep/path", severity="critical"),
            _finding("b", "http://x/", severity="low"),
        ],
    }
    report = build_attack_path(doc)
    assert [n["id"] for n in report["nodes"]] == ["b", "a"]


def test_render_markdown_mentions_heuristic_disclaimer_and_findings():
    doc = {"target": "http://x", "findings": [_finding("missing-hsts", "http://x/a")]}
    report = build_attack_path(doc)
    md = render_attack_path_markdown(report)
    assert "heuristic" in md.lower()
    assert "missing-hsts" in md
