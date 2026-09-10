from __future__ import annotations

from shroodler.pacer import Pacer
from shroodler.probes.xss import probe_xss


class FakeResp:
    def __init__(self, status=200, text=""):
        self.status_code = status
        self.text = text
        self.content = text.encode()
        self.headers = {}


class FakeClient:
    def __init__(self, handler):
        self.handler = handler

    def request(self, method, url, **kw):
        return self.handler(method, url, kw)

    def close(self):
        pass


def _injected(kw) -> str:
    params = kw.get("params") or {}
    data = kw.get("data") or {}
    json_body = kw.get("json") or {}
    blobs = []
    if isinstance(params, dict):
        blobs.extend(str(v) for v in params.values())
    if isinstance(data, dict):
        blobs.extend(str(v) for v in data.values())
    if isinstance(json_body, dict):
        blobs.extend(str(v) for v in json_body.values())
    return " ".join(blobs)


def test_xss_reflected_confirmed():
    def handler(method, url, kw):
        injected = _injected(kw)
        if "shroodler-xss-" in injected:
            return FakeResp(200, f"echo {injected}")
        return FakeResp(200, "clean")

    findings = probe_xss(
        "http://127.0.0.1/search",
        "GET",
        [{"name": "q"}],
        "session=owner",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    hit = next(f for f in findings if f.id == "xss-reflected")
    assert hit.severity == "high"
    assert hit.confidence == "confirmed"
    assert hit.category == "payload"


def test_xss_stored_confirmed_on_follow_get():
    stored = {"nonce": ""}

    def handler(method, url, kw):
        injected = _injected(kw)
        if "shroodler-xss-" in injected:
            start = injected.find("shroodler-xss-") + len("shroodler-xss-")
            stored["nonce"] = injected[start : start + 6]
            return FakeResp(200, "saved")
        if method == "GET" and stored["nonce"]:
            return FakeResp(200, f"comment body {stored['nonce']}")
        return FakeResp(200, "clean")

    findings = probe_xss(
        "http://127.0.0.1/comments",
        "POST",
        [{"name": "body"}],
        "session=owner",
        view_url="http://127.0.0.1/comments",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    hit = next(f for f in findings if f.id == "xss-stored")
    assert hit.severity == "critical"
    assert hit.confidence == "confirmed"


def test_xss_stored_put_json_reads_view_url():
    stored = {"nonce": ""}

    def handler(method, url, kw):
        injected = _injected(kw)
        if "shroodler-xss-" in injected:
            start = injected.find("shroodler-xss-") + len("shroodler-xss-")
            stored["nonce"] = injected[start : start + 6]
            return FakeResp(200, '{"status":"success"}')
        if method == "GET" and "reviews" in url and stored["nonce"]:
            return FakeResp(
                200,
                f"<script>alert('shroodler-xss-{stored['nonce']}')</script>",
            )
        return FakeResp(200, "clean")

    findings = probe_xss(
        "http://127.0.0.1/rest/products/1/reviews",
        "PUT",
        [{"name": "message", "in": "json"}],
        "session=owner",
        view_url="http://127.0.0.1/rest/products/1/reviews",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    hit = next(f for f in findings if f.id == "xss-stored")
    assert hit.severity == "critical"
    assert hit.confidence == "confirmed"
    assert hit.category == "payload"
    assert "param=message" in (hit.evidence or "")


def test_xss_skips_when_no_params():
    findings = probe_xss(
        "http://127.0.0.1/page",
        "GET",
        [],
        "",
        client=FakeClient(lambda *a, **k: FakeResp(200, "<script>alert('x')</script>")),
        pacer=Pacer(0),
    )
    assert findings == []


def test_xss_network_error_returns_empty():
    class Boom:
        def request(self, *a, **k):
            raise ConnectionError("down")

        def close(self):
            pass

    findings = probe_xss(
        "http://127.0.0.1/search",
        "GET",
        [{"name": "q"}],
        "",
        client=Boom(),
        pacer=Pacer(0),
    )
    assert findings == []
