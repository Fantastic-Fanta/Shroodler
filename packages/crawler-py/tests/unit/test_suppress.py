from __future__ import annotations

import datetime

from shroodler.suppress import (
    expired_suppressions,
    expiring_within,
    filter_findings,
    finding_suppressed,
    is_expired,
    parse_suppressions,
    render_expiring_pr_body,
)


def _finding(fid: str, url: str) -> dict:
    return {"id": fid, "url": url}


def test_rule_without_expires_never_expires():
    rules = parse_suppressions('[{"id": "missing-csp", "url": "*"}]')
    assert rules[0]["expires"] is None
    assert not is_expired(rules[0], today=datetime.date(2099, 1, 1))


def test_rule_with_future_expires_is_not_yet_expired():
    rules = parse_suppressions('[{"id": "missing-csp", "url": "*", "expires": "2099-01-01"}]')
    assert not is_expired(rules[0], today=datetime.date(2026, 1, 1))


def test_rule_with_past_expires_is_expired():
    rules = parse_suppressions('[{"id": "missing-csp", "url": "*", "expires": "2020-01-01"}]')
    assert is_expired(rules[0], today=datetime.date(2026, 1, 1))


def test_rule_expiring_today_is_not_yet_expired():
    # Expires ON that date, not before it -- the suppression is still
    # valid through the end of its expiry day.
    rules = parse_suppressions('[{"id": "missing-csp", "url": "*", "expires": "2026-06-01"}]')
    assert not is_expired(rules[0], today=datetime.date(2026, 6, 1))
    assert is_expired(rules[0], today=datetime.date(2026, 6, 2))


def test_unparseable_expires_fails_safe_to_already_expired():
    rules = parse_suppressions('[{"id": "missing-csp", "url": "*", "expires": "not-a-date"}]')
    assert is_expired(rules[0], today=datetime.date(2026, 1, 1))


def test_non_string_expires_fails_safe_instead_of_crashing():
    from shroodler.suppress import expires_malformed

    # A hand-built rule dict (bypassing parse_suppressions' str()
    # coercion) with a non-string expires (e.g. unquoted YAML int) must
    # fail safe like any other malformed value, not raise AttributeError
    # from calling .strip() on an int.
    rule = {"id": "a", "url": "*", "owner": "", "expires": 20250101}
    assert is_expired(rule, today=datetime.date(2020, 1, 1))
    assert expires_malformed(rule)


def test_expired_suppression_no_longer_suppresses_the_finding():
    rules = parse_suppressions('[{"id": "missing-csp", "url": "*", "expires": "2020-01-01"}]')
    finding = _finding("missing-csp", "http://x/")
    assert finding_suppressed(finding, rules, today=datetime.date(2026, 1, 1)) is None
    assert filter_findings([finding], rules, today=datetime.date(2026, 1, 1)) == [finding]


def test_unexpired_suppression_still_suppresses_the_finding():
    rules = parse_suppressions('[{"id": "missing-csp", "url": "*", "expires": "2099-01-01"}]')
    finding = _finding("missing-csp", "http://x/")
    assert finding_suppressed(finding, rules, today=datetime.date(2026, 1, 1)) is not None
    assert filter_findings([finding], rules, today=datetime.date(2026, 1, 1)) == []


def test_expired_suppressions_lists_only_expired_rules():
    rules = parse_suppressions(
        '[{"id": "a", "url": "*", "expires": "2020-01-01"},'
        '{"id": "b", "url": "*", "expires": "2099-01-01"},'
        '{"id": "c", "url": "*"}]'
    )
    expired = expired_suppressions(rules, today=datetime.date(2026, 1, 1))
    assert {r["id"] for r in expired} == {"a"}


def test_owner_field_is_parsed():
    rules = parse_suppressions('[{"id": "missing-csp", "url": "*", "owner": "security-team"}]')
    assert rules[0]["owner"] == "security-team"


def test_owner_defaults_to_empty_string():
    rules = parse_suppressions('[{"id": "missing-csp", "url": "*"}]')
    assert rules[0]["owner"] == ""


def test_present_but_empty_expires_is_treated_as_malformed_not_absent():
    # Regression test: a truthiness check on expires_raw treated
    # "expires": "" (present but empty/falsy) the same as the key being
    # entirely absent -- silently disabling the whole feature for a rule
    # whose expires field got cleared out or misconfigured, exactly
    # backwards for a mechanism meant to force re-review rather than
    # silently accept risk forever.
    rules = parse_suppressions('[{"id": "a", "url": "*", "expires": ""}]')
    assert is_expired(rules[0], today=datetime.date(2026, 1, 1))


def test_expires_with_whitespace_is_still_parsed():
    rules = parse_suppressions('[{"id": "a", "url": "*", "expires": " 2099-01-01 "}]')
    assert not is_expired(rules[0], today=datetime.date(2026, 1, 1))


def test_absent_expires_key_is_distinct_from_present_but_empty():
    from shroodler.suppress import expires_malformed

    absent = parse_suppressions('[{"id": "a", "url": "*"}]')[0]
    empty = parse_suppressions('[{"id": "a", "url": "*", "expires": ""}]')[0]
    assert not expires_malformed(absent)
    assert expires_malformed(empty)


def test_expires_malformed_true_for_bad_string_false_for_real_dates():
    from shroodler.suppress import expires_malformed

    bad = parse_suppressions('[{"id": "a", "url": "*", "expires": "not-a-date"}]')[0]
    good_past = parse_suppressions('[{"id": "a", "url": "*", "expires": "2020-01-01"}]')[0]
    good_future = parse_suppressions('[{"id": "a", "url": "*", "expires": "2099-01-01"}]')[0]
    assert expires_malformed(bad)
    assert not expires_malformed(good_past)
    assert not expires_malformed(good_future)


def test_expiring_within_includes_rule_inside_horizon():
    today = datetime.date(2020, 1, 1)
    rules = parse_suppressions('[{"id": "a", "url": "*", "expires": "2020-01-10"}]')
    assert expiring_within(rules, 14, today=today) == rules


def test_expiring_within_excludes_rule_beyond_horizon():
    today = datetime.date(2020, 1, 1)
    rules = parse_suppressions('[{"id": "a", "url": "*", "expires": "2020-02-01"}]')
    assert expiring_within(rules, 14, today=today) == []


def test_expiring_within_excludes_already_expired_rule():
    today = datetime.date(2020, 1, 10)
    rules = parse_suppressions('[{"id": "a", "url": "*", "expires": "2020-01-01"}]')
    assert expiring_within(rules, 14, today=today) == []


def test_expiring_within_excludes_never_expiring_and_malformed():
    today = datetime.date(2020, 1, 1)
    rules = parse_suppressions(
        '[{"id": "a", "url": "*"}, {"id": "b", "url": "*", "expires": "not-a-date"}]'
    )
    assert expiring_within(rules, 14, today=today) == []


def test_render_expiring_pr_body_empty():
    body = render_expiring_pr_body([], 14)
    assert "No suppression rules expire" in body


def test_render_expiring_pr_body_lists_rules():
    rules = parse_suppressions(
        '[{"id": "missing-hsts", "url": "/a", "expires": "2020-01-10", '
        '"owner": "team-x", "reason": "known issue"}]'
    )
    body = render_expiring_pr_body(rules, 14)
    assert "missing-hsts" in body
    assert "team-x" in body
    assert "known issue" in body
    assert "2020-01-10" in body


def test_render_expiring_pr_body_escapes_markdown_control_chars():
    rules = parse_suppressions(
        '[{"id": "a`evil", "url": "/x", "expires": "2020-01-10", '
        '"owner": "team", "reason": "line1\\nline2 | pipe ` backtick"}]'
    )
    body = render_expiring_pr_body(rules, 14)
    lines = [ln for ln in body.split("\n") if ln.strip()]
    # One rule -> exactly one intro line plus one rule line; an
    # unescaped embedded newline in `reason` would have produced more.
    assert len(lines) == 2
    assert "a`evil" not in body
    assert "line1 line2" in body


def test_render_expiring_pr_body_reason_cannot_inject_a_markdown_link():
    # round-2 fix: owner/reason are placed in prose, not just id/url --
    # a hostile reason must not render as a live Markdown link in a PR
    # body a CI job posts unattended.
    rules = parse_suppressions(
        '[{"id": "a", "url": "/x", "expires": "2020-01-10", "owner": "team", '
        '"reason": "legit [click here](http://evil.example/)"}]'
    )
    body = render_expiring_pr_body(rules, 14)
    # The reason text is wrapped in its own code span, so the markdown
    # link syntax renders as literal text, not a clickable link.
    assert "reason: `legit [click here](http://evil.example/)`" in body
