from __future__ import annotations

from shroodler.pacer import Pacer
from shroodler.probes.smuggling import probe_smuggling


class FakeResp:
    def __init__(self, status=200, text="ok", elapsed=0.01):
        self.status_code = status
        self.text = text
        self.content = text.encode()
        self.headers = {}
        self.elapsed = elapsed


class FakeClient:
    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def request(self, method, url, **kw):
        self.calls.append((method, url, kw))
        return self.handler(method, url, kw)

    def close(self):
        pass


def test_cl_te_timing_is_heuristic(monkeypatch):
    clock = iter([0.0, 0.01, 10.0, 16.0, 16.0, 16.01, 16.01, 16.02, 16.02, 16.03])
    monkeypatch.setattr("shroodler.probes.smuggling.time.monotonic", lambda: next(clock, 16.03))

    def handler(method, url, kw):
        headers = kw.get("headers") or {}
        te = headers.get("Transfer-Encoding")
        if te == "chunked" and str(headers.get("Content-Length")) == "6":
            return FakeResp(200, "slow", elapsed=6.2)
        return FakeResp(200, "ok", elapsed=0.05)

    findings = probe_smuggling(
        "http://127.0.0.1/login",
        "",
        allow_external=False,
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    hit = next(f for f in findings if f.id == "http-smuggling-cl-te")
    assert hit.severity == "critical"
    assert hit.confidence == "heuristic"
    assert hit.category == "payload"


def test_te_te_obfuscation_status_change():
    def handler(method, url, kw):
        headers = kw.get("headers") or {}
        te = headers.get("Transfer-Encoding")
        if te == "xchunked":
            return FakeResp(400, "bad te")
        return FakeResp(200, "ok")

    findings = probe_smuggling(
        "http://127.0.0.1/",
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    hit = next(f for f in findings if f.id == "http-smuggling-te-te")
    assert hit.confidence == "heuristic"
    assert "xchunked" in (hit.evidence or "")


def test_smuggling_skips_external_without_allow():
    findings = probe_smuggling(
        "https://example.com/login",
        "",
        allow_external=False,
        client=FakeClient(lambda *a, **k: FakeResp()),
        pacer=Pacer(0),
    )
    assert findings == []


def test_no_real_sleep_on_timing_path(monkeypatch):
    slept = []
    monkeypatch.setattr("time.sleep", lambda s: slept.append(s))
    clock = iter([0.0, 0.01, 0.02, 0.03, 0.04, 0.05, 0.06, 0.07, 0.08, 0.09, 0.10])
    monkeypatch.setattr("shroodler.probes.smuggling.time.monotonic", lambda: next(clock, 0.10))
    probe_smuggling(
        "http://127.0.0.1/",
        "",
        client=FakeClient(lambda *a, **k: FakeResp(elapsed=0.01)),
        pacer=Pacer(0),
    )
    assert slept == []
