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


def test_path_depth_decodes_percent_encoded_slashes():
    # A genuinely deep path (/a/b/c/critical, decoded) written with
    # percent-encoded slashes must not be miscounted as depth 1 -- that
    # would sort a deeply-nested critical finding to the top of the
    # report as if it were the shallowest/most-exposed one.
    doc = {
        "target": "http://x",
        "findings": [_finding("payload-sql-error", "http://x/a%2Fb%2Fc%2Fcritical")],
    }
    report = build_attack_path(doc)
    assert report["nodes"][0]["path_depth"] == 4


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


def test_auth_category_finding_gets_token_context_note_when_same_subsystem():
    # Both under the same top-level path segment ("account") -- scoped
    # correlation, not "any weak token anywhere in the scan".
    doc = {
        "target": "http://x",
        "findings": [
            _finding("reset-token-short", "http://x/account/reset", category="auth"),
            _finding("authz-still-accessible", "http://x/account/profile", category="auth"),
        ],
    }
    report = build_attack_path(doc)
    node = next(n for n in report["nodes"] if n["id"] == "authz-still-accessible")
    assert node["relevant_token_context"] is True
    assert "guessable session/reset token" in node["narrative"]


def test_auth_category_finding_not_flagged_when_different_subsystem():
    # A weak token under /reset and an unrelated auth finding under
    # /billing must not be correlated just because both are "auth"
    # category somewhere in the same scan -- that's the noisy,
    # boilerplate-inducing behavior this scoping fixes.
    doc = {
        "target": "http://x",
        "findings": [
            _finding("reset-token-short", "http://x/reset", category="auth"),
            _finding("authz-still-accessible", "http://x/billing/account", category="auth"),
        ],
    }
    report = build_attack_path(doc)
    node = next(n for n in report["nodes"] if n["id"] == "authz-still-accessible")
    assert node["relevant_token_context"] is False


def test_generic_top_segment_requires_second_segment_to_match():
    # /api/v1/reset-password and /api/v1/account/settings share top-level
    # segment "api" -- too generic to mean anything on a typical REST
    # API/SPA backend, where nearly everything lives under one "api"
    # prefix. Matching top-segment alone would reintroduce the exact
    # scan-wide noise problem the subsystem scoping fixed.
    doc = {
        "target": "http://x",
        "findings": [
            _finding("reset-token-short", "http://x/api/v1/reset-password", category="auth"),
            _finding(
                "authz-still-accessible",
                "http://x/api/v1/account/settings",
                category="auth",
            ),
        ],
    }
    report = build_attack_path(doc)
    node = next(n for n in report["nodes"] if n["id"] == "authz-still-accessible")
    assert node["relevant_token_context"] is False


def test_generic_top_segment_matches_when_second_segment_agrees():
    doc = {
        "target": "http://x",
        "findings": [
            _finding("reset-token-short", "http://x/api/account/reset", category="auth"),
            _finding(
                "authz-still-accessible",
                "http://x/api/account/settings",
                category="auth",
            ),
        ],
    }
    report = build_attack_path(doc)
    node = next(n for n in report["nodes"] if n["id"] == "authz-still-accessible")
    assert node["relevant_token_context"] is True


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


def test_cmd_attack_path_cli_writes_json(tmp_path):
    import argparse
    import json

    from shroodler.cli import cmd_attack_path

    findings_path = tmp_path / "f.json"
    findings_path.write_text(
        json.dumps({"target": "http://x", "findings": [_finding("missing-hsts", "http://x/a")]}),
        encoding="utf-8",
    )
    out = tmp_path / "out.json"
    ns = argparse.Namespace(findings=str(findings_path), format="json", output=str(out))
    assert cmd_attack_path(ns) == 0
    result = json.loads(out.read_text(encoding="utf-8"))
    assert result["nodes"][0]["id"] == "missing-hsts"
