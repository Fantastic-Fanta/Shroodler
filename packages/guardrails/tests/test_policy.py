from __future__ import annotations

import json

import httpx
import pytest
from shroodler_guardrails.policy import (
    PolicyEnforcer,
    PolicyViolation,
    fetch_policy,
    parse_policy,
    policy_hash,
)


def test_parse_policy_defaults():
    p = parse_policy({})
    assert p.allow == ("*",)
    assert p.deny == ()
    assert p.max_requests_per_minute > 0


def test_covers_allow_deny_precedence():
    p = parse_policy({"allow": ["/api/*"], "deny": ["/api/admin/*"]})
    assert p.covers("https://x.test/api/users")
    assert not p.covers("https://x.test/api/admin/delete")
    assert not p.covers("https://x.test/other")


def test_expired():
    p = parse_policy({"expires": "2000-01-01"})
    assert p.is_expired()
    p2 = parse_policy({"expires": "2999-01-01"})
    assert not p2.is_expired()
    p3 = parse_policy({"expires": "not-a-date"})
    assert p3.is_expired()


def test_hash_stable_regardless_of_key_order():
    a = {"allow": ["*"], "contact": "x"}
    b = {"contact": "x", "allow": ["*"]}
    assert policy_hash(a) == policy_hash(b)


def test_enforcer_requires_policy_when_asked():
    with pytest.raises(PolicyViolation):
        PolicyEnforcer(policy=None, require_policy=True)


def test_enforcer_rejects_expired_policy():
    p = parse_policy({"expires": "2000-01-01"})
    with pytest.raises(PolicyViolation):
        PolicyEnforcer(policy=p)


def test_enforcer_scope_and_rate_limit(tmp_path):
    p = parse_policy({"allow": ["/ok/*"], "max_requests_per_minute": 2, "max_total_requests": 3})
    audit = tmp_path / "audit.jsonl"
    enforcer = PolicyEnforcer(policy=p, audit_path=audit)

    allowed, reason = enforcer.check("https://x.test/blocked/path")
    assert not allowed
    assert "scope" in reason

    ok1, _ = enforcer.check("https://x.test/ok/a")
    ok2, _ = enforcer.check("https://x.test/ok/b")
    ok3, reason3 = enforcer.check("https://x.test/ok/c")
    assert ok1 and ok2
    assert not ok3
    assert "rate limit" in reason3

    events = [json.loads(line) for line in audit.read_text().splitlines()]
    assert len(events) == 4
    assert events[0]["policy_hash"] == policy_hash(p)

    summary = enforcer.summary()
    assert summary["requests_attempted"] == 4
    assert summary["requests_blocked"] == 2


def test_enforcer_blast_radius():
    p = parse_policy({"max_total_requests": 1, "max_requests_per_minute": 100})
    enforcer = PolicyEnforcer(policy=p)
    ok1, _ = enforcer.check("https://x.test/a")
    ok2, reason2 = enforcer.check("https://x.test/b")
    assert ok1
    assert not ok2
    assert "blast-radius" in reason2


def test_fetch_policy_success():
    manifest = {"allow": ["/*"], "contact": "sec@example.test"}

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/.well-known/scan-policy.json"
        return httpx.Response(200, json=manifest)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    policy = fetch_policy("https://example.test", client=client)
    assert policy is not None
    assert policy.contact == "sec@example.test"


def test_fetch_policy_missing_returns_none():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    assert fetch_policy("https://example.test", client=client) is None
