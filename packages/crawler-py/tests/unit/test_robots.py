from __future__ import annotations

from shroodler.robots import disallow_paths


def test_disallow_paths_generic_agent_only():
    body = (
        "User-agent: *\n"
        "Disallow: /admin\n"
        "Disallow: /backup\n"
        "User-agent: BadBot\n"
        "Disallow: /bot-only\n"
    )
    assert disallow_paths(body) == ["/admin", "/backup"]


def test_disallow_paths_skips_empty_and_root_and_comments():
    body = (
        "# a comment line\n"
        "Disallow: /before-agent\n"  # rules before any agent apply broadly
        "User-agent: *\n"
        "Disallow:\n"  # empty = allow all, not a lead
        "Disallow: /\n"  # block-everything, not a specific lead
        "Disallow: /secret # trailing comment\n"
    )
    assert disallow_paths(body) == ["/before-agent", "/secret"]


def test_disallow_paths_dedupes_in_order():
    body = "User-agent: *\nDisallow: /a\nDisallow: /b\nDisallow: /a\n"
    assert disallow_paths(body) == ["/a", "/b"]


def test_disallow_paths_empty_body():
    assert disallow_paths("") == []
