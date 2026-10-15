from __future__ import annotations

from datetime import timedelta

from shroodler.pacer import Pacer
from shroodler.probes.nosql import probe_nosql


class FakeResp:
    def __init__(self, status=200, text="", elapsed=0.0):
        self.status_code = status
        self.text = text
        self.content = text.encode()
        self.elapsed = timedelta(seconds=elapsed)
        self.headers = {}


class FakeClient:
    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def request(self, method, url, **kw):
        self.calls.append((method, url, kw))
        return self.handler(method, url, kw)

    def close(self):
        pass


def _values(kw) -> list[str]:
    out: list[str] = []
    for key in ("params", "data"):
        blob = kw.get(key) or {}
        if isinstance(blob, dict):
            out.extend(str(v) for v in blob.values())
    body = kw.get("json")
    if isinstance(body, dict):
        out.extend(str(v) for v in body.values())
    return out


def test_nosql_error_based_confirmed():
    def handler(method, url, kw):
        if any(ch in v for v in _values(kw) for ch in ("'", '"', "{", "\\", "$")):
            return FakeResp(500, "MongoServerError: unknown operator $gt")
        return FakeResp(200, "ok")

    findings = probe_nosql(
        "http://127.0.0.1/users",
        "GET",
        [{"name": "filter", "value": "alice"}],
        "session=owner",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    hit = next(f for f in findings if f.id == "nosqli")
    assert hit.severity == "critical"
    assert hit.confidence == "confirmed"
    assert hit.category == "payload"
    assert hit.url == "http://127.0.0.1/users"


def test_nosql_baseline_error_is_not_a_finding():
    # The endpoint always returns a Mongo error, even on a clean value, so the
    # error is not payload-induced and must not be reported.
    def handler(method, url, kw):
        return FakeResp(500, "MongoError: connection refused")

    findings = probe_nosql(
        "http://127.0.0.1/users",
        "GET",
        [{"name": "filter", "value": "alice"}],
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    assert [f for f in findings if f.id == "nosqli"] == []


def test_nosql_operator_boolean_differential():
    # $where-style injection: baseline and always-true return the full list;
    # always-false returns an empty list.
    full = "[" + ",".join(f'{{"id":{i}}}' for i in range(40)) + "]"

    def handler(method, url, kw):
        vals = _values(kw)
        if any("=='2" in v for v in vals):  # always-false payload
            return FakeResp(200, "[]")
        return FakeResp(200, full)

    findings = probe_nosql(
        "http://127.0.0.1/search",
        "GET",
        [{"name": "q", "value": "widget"}],
        "session=owner",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    hit = next(f for f in findings if f.id == "nosqli-operator")
    assert hit.severity == "high"
    assert hit.confidence == "heuristic"


def test_nosql_reflective_param_is_not_flagged():
    # A param whose raw value is echoed back makes baseline and true-payload
    # bodies differ, so the boolean-differential guard rejects it.
    def handler(method, url, kw):
        vals = _values(kw)
        reflected = vals[0] if vals else ""
        return FakeResp(200, f"you searched for: {reflected}")

    findings = probe_nosql(
        "http://127.0.0.1/search",
        "GET",
        [{"name": "q", "value": "widget"}],
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    assert findings == []


def test_nosql_skips_when_no_params():
    called = []

    def handler(method, url, kw):
        called.append(url)
        return FakeResp(200, "MongoError")

    findings = probe_nosql(
        "http://127.0.0.1/users",
        "GET",
        [],
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    assert findings == []
    assert called == []


def test_nosql_challenge_is_coverage_gap():
    bad = ("$", "{", "[", "'", ";", "|")

    def handler(method, url, kw):
        blob = " ".join(_values(kw))
        if any(ch in blob for ch in bad):
            return FakeResp(403, "Just a moment...")
        return FakeResp(200, "ok")

    findings = probe_nosql(
        "http://127.0.0.1/api/users",
        "GET",
        [{"name": "id", "value": "1"}],
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    assert [f for f in findings if f.id.startswith("nosqli")] == []
    gap = next(f for f in findings if f.id == "probe-challenged-nosql")
    assert gap.category == "waf-challenge"
