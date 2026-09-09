from __future__ import annotations

from shroodler.pacer import Pacer
from shroodler.probes.rate_limit import looks_auth_url, probe_rate_limit


class FakeResp:
    def __init__(self, status=200, headers=None):
        self.status_code = status
        self.text = "ok"
        self.content = b"ok"
        self.headers = headers or {}


class FakeClient:
    def __init__(self, statuses, headers=None):
        self.statuses = list(statuses)
        self.headers = headers or {}
        self.calls = []

    def request(self, method, url, **kw):
        self.calls.append((method, url, kw))
        status = self.statuses.pop(0) if self.statuses else 200
        return FakeResp(status, dict(self.headers))

    def close(self):
        pass


def test_looks_auth_url():
    assert looks_auth_url("http://127.0.0.1/login")
    assert looks_auth_url("http://127.0.0.1/api/auth/token")
    assert looks_auth_url("http://127.0.0.1/password/reset")
    assert not looks_auth_url("http://127.0.0.1/search")


def test_missing_rate_limit_on_fifteen_200s():
    client = FakeClient([200] * 15)
    findings = probe_rate_limit(
        "http://127.0.0.1/login",
        "POST",
        "",
        client=client,
        pacer=Pacer(0),
    )
    hit = findings[0]
    assert hit.id == "missing-rate-limit"
    assert hit.severity == "medium"
    assert hit.confidence == "confirmed"
    assert hit.category == "auth"
    assert len(client.calls) == 15
    header = (client.calls[0][2].get("headers") or {}).get("X-Shroodler-RL-Test")
    assert header


def test_no_finding_when_one_429():
    findings = probe_rate_limit(
        "http://127.0.0.1/login",
        "POST",
        "",
        client=FakeClient([200] * 14 + [429]),
        pacer=Pacer(0),
    )
    assert findings == []


def test_no_finding_when_ratelimit_header_present():
    findings = probe_rate_limit(
        "http://127.0.0.1/login",
        "POST",
        "",
        client=FakeClient([200] * 15, headers={"X-RateLimit-Remaining": "3"}),
        pacer=Pacer(0),
    )
    assert findings == []


def test_skips_non_auth_urls():
    findings = probe_rate_limit(
        "http://127.0.0.1/search",
        "GET",
        "",
        client=FakeClient([200] * 15),
        pacer=Pacer(0),
    )
    assert findings == []
