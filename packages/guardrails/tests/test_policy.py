from __future__ import annotations

import json

import httpx
import pytest
from shroodler_guardrails.policy import (
    HARD_MAX_REQUESTS_PER_MINUTE,
    HARD_MAX_TOTAL_REQUESTS,
    PolicyEnforcer,
    PolicyViolation,
    fetch_policy,
    origin_of,
    parse_policy,
    policy_hash,
    verify_audit_log,
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


def test_fetch_policy_refuses_plain_http_for_non_local_target():
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("should never be called: plain HTTP to a public host")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    assert fetch_policy("http://example.test", client=client) is None


def test_fetch_policy_allows_plain_http_for_localhost():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"allow": ["*"]})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    policy = fetch_policy("http://127.0.0.1:8080", client=client)
    assert policy is not None


def test_fetch_policy_rejects_oversized_manifest():
    huge = {"allow": ["/x"], "contact": "a" * 200_000}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=huge)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    assert fetch_policy("https://example.test", client=client) is None


def test_origin_of():
    assert origin_of("https://x.test/a") == "https://x.test:"
    assert origin_of("https://x.test:8443/a") == "https://x.test:8443"


def test_covers_rejects_mismatched_origin():
    p = parse_policy({"allow": ["*"]}, origin="https://x.test:")
    assert p.covers("https://x.test/anything")
    assert not p.covers("https://evil.test/anything")
    assert not p.covers("http://x.test/anything")  # scheme differs too


def test_covers_normalizes_percent_encoding_against_deny():
    p = parse_policy({"allow": ["*"], "deny": ["/admin/*"]}, origin="https://x.test:")
    assert not p.covers("https://x.test/admin/delete")
    assert not p.covers("https://x.test/admin%2Fdelete")
    assert not p.covers("https://x.test/ADMIN".lower() + "/delete")


def test_covers_normalizes_dot_segments_against_allow_escape():
    # A request that *looks* like it targets an allowed prefix but really
    # resolves (after ../ collapsing) into a denied one must not sneak
    # through as "allowed".
    p = parse_policy({"allow": ["/public/*"], "deny": ["/admin/*"]}, origin="https://x.test:")
    assert not p.covers("https://x.test/public/../admin/delete")


def test_manifest_cannot_raise_limits_past_hard_ceiling():
    p = parse_policy(
        {"max_requests_per_minute": 10**9, "max_total_requests": 10**9},
        origin="https://x.test:",
    )
    assert p.max_requests_per_minute == HARD_MAX_REQUESTS_PER_MINUTE
    assert p.max_total_requests == HARD_MAX_TOTAL_REQUESTS


def test_enforcer_caller_ceiling_wins_over_manifest():
    p = parse_policy({"max_requests_per_minute": 1000}, origin="https://x.test:")
    enforcer = PolicyEnforcer(policy=p, rpm_ceiling=1)
    ok1, _ = enforcer.check("https://x.test/a")
    ok2, reason2 = enforcer.check("https://x.test/b")
    assert ok1
    assert not ok2
    assert "rate limit" in reason2


def test_audit_log_hash_chain_detects_tampering(tmp_path):
    audit = tmp_path / "audit.jsonl"
    p = parse_policy({"allow": ["/ok/*"]}, origin="https://x.test:")
    enforcer = PolicyEnforcer(policy=p, audit_path=audit)
    enforcer.check("https://x.test/ok/a")
    enforcer.check("https://x.test/ok/b")

    assert verify_audit_log(audit) == []

    lines = audit.read_text().splitlines()
    tampered = json.loads(lines[0])
    tampered["allowed"] = False  # flip a decision after the fact
    lines[0] = json.dumps(tampered)
    audit.write_text("\n".join(lines) + "\n")

    problems = verify_audit_log(audit)
    assert problems, "tampering with a past entry should be detected"
