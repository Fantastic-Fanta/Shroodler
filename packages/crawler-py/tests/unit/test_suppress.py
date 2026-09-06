from __future__ import annotations

import datetime

from shroodler.suppress import (
    expired_suppressions,
    filter_findings,
    finding_suppressed,
    is_expired,
    parse_suppressions,
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
