from __future__ import annotations

from shroodler.pacer import Pacer
from shroodler.probes.idor import probe_idor


class FakeResp:
    def __init__(self, status=200, text=""):
        self.status_code = status
        self.text = text
        self.content = text.encode()
        self.headers = {}

    def json(self):
        import json

        return json.loads(self.text)


class FakeClient:
    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def request(self, method, url, **kw):
        self.calls.append((method, url, kw))
        return self.handler(method, url, kw)

    def close(self):
        pass


def _cookie(kw) -> str:
    headers = kw.get("headers") or {}
    return headers.get("Cookie") or ""


def test_idor_peer_200_vs_anon_401():
    def handler(method, url, kw):
        cookie = _cookie(kw)
        if url.endswith("/profile/me"):
            return FakeResp(200, '{"id": 200000}')
        if not cookie:
            return FakeResp(401, "")
        if "100001" in url or "200000" in url:
            return FakeResp(200, '{"order": 99, "secret": "peer-visible"}')
        return FakeResp(200, '{"order": 1}')

    findings = probe_idor(
        "http://127.0.0.1/orders/100000",
        "session=owner",
        "session=peer",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    hit = findings[0]
    assert hit.id == "idor"
    assert hit.severity == "high"
    assert hit.confidence == "confirmed"
    assert hit.category == "auth"
    assert "100001" in hit.url or "200000" in hit.url


def test_idor_skips_without_peer_cookie():
    findings = probe_idor(
        "http://127.0.0.1/orders/100000",
        "session=owner",
        "",
        client=FakeClient(lambda *a, **k: FakeResp(200, "x")),
        pacer=Pacer(0),
    )
    assert findings == []


def test_idor_skips_short_numeric_ids():
    findings = probe_idor(
        "http://127.0.0.1/orders/123",
        "session=owner",
        "session=peer",
        client=FakeClient(lambda *a, **k: FakeResp(200, "x")),
        pacer=Pacer(0),
    )
    assert findings == []


def test_idor_no_finding_when_anon_also_200():
    def handler(method, url, kw):
        return FakeResp(200, '{"order": 1}')

    findings = probe_idor(
        "http://127.0.0.1/orders/100000",
        "session=owner",
        "session=peer",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    assert findings == []


def test_idor_network_error_returns_empty():
    class Boom:
        def request(self, *a, **k):
            raise ConnectionError("down")

        def close(self):
            pass

    findings = probe_idor(
        "http://127.0.0.1/orders/100000",
        "session=owner",
        "session=peer",
        client=Boom(),
        pacer=Pacer(0),
    )
    assert findings == []
