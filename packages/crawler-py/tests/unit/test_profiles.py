from __future__ import annotations

from shroodler.cli import PROFILES, _apply_profile, _profile_from_argv, build_parser


def test_profile_from_argv_space_separated():
    assert _profile_from_argv(["crawl", "http://x/", "--profile", "aggressive"]) == "aggressive"


def test_profile_from_argv_equals_form():
    assert _profile_from_argv(["crawl", "http://x/", "--profile=safe"]) == "safe"


def test_profile_from_argv_absent():
    assert _profile_from_argv(["crawl", "http://x/"]) is None


def test_apply_profile_sets_crawl_defaults():
    p = build_parser()
    _apply_profile(p, "aggressive")
    args = p.parse_args(["crawl", "http://127.0.0.1:1"])
    preset = PROFILES["aggressive"]
    assert args.depth == preset["depth"]
    assert args.max_pages == preset["max_pages"]
    assert args.max_time == preset["max_time"]
    assert args.check_rate_limit == preset["check_rate_limit"]


def test_apply_profile_explicit_flag_still_wins():
    p = build_parser()
    _apply_profile(p, "safe")
    args = p.parse_args(["crawl", "http://127.0.0.1:1", "--depth", "9", "--check-rate-limit"])
    assert args.depth == 9
    assert args.check_rate_limit is True
    # untouched flags still take the profile's value
    assert args.max_pages == PROFILES["safe"]["max_pages"]


def test_unknown_profile_name_rejected_by_argparse():
    import pytest

    p = build_parser()
    with pytest.raises(SystemExit):
        p.parse_args(["crawl", "http://127.0.0.1:1", "--profile", "bogus"])


def test_all_profiles_produce_valid_parse():
    for name in PROFILES:
        p = build_parser()
        _apply_profile(p, name)
        args = p.parse_args(["crawl", "http://127.0.0.1:1", "--profile", name])
        assert args.profile == name


def test_no_check_rate_limit_overrides_aggressive_profile():
    p = build_parser()
    _apply_profile(p, "aggressive")
    assert PROFILES["aggressive"]["check_rate_limit"] is True
    args = p.parse_args(["crawl", "http://127.0.0.1:1", "--no-check-rate-limit"])
    assert args.check_rate_limit is False


def test_check_rate_limit_defaults_false_without_any_profile():
    p = build_parser()
    args = p.parse_args(["crawl", "http://127.0.0.1:1"])
    assert args.check_rate_limit is False


def test_profile_wins_over_rc_file():
    from shroodler.cli import _apply_rc

    p = build_parser()
    _apply_rc(p, {"depth": 2})
    _apply_profile(p, "aggressive")
    args = p.parse_args(["crawl", "http://127.0.0.1:1"])
    # aggressive's depth (-1) must win over the rc file's depth (2) -- a
    # profile picked explicitly on the command line should not be
    # silently overridden by a static config file.
    assert args.depth == PROFILES["aggressive"]["depth"]
