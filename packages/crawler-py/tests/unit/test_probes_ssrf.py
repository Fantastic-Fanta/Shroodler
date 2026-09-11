from __future__ import annotations

from datetime import timedelta

from shroodler.pacer import Pacer
from shroodler.probes.ssrf import probe_ssrf


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
    params = kw.get("params") or {}
    data = kw.get("data") or {}
    out: list[str] = []
    if isinstance(params, dict):
        out.extend(str(v) for v in params.values())
    if isinstance(data, dict):
        out.extend(str(v) for v in data.values())
    return out


def _listen_hit(timeout: float):
    return 54321, lambda: True


def _listen_miss(timeout: float):
    return 54321, lambda: False


def test_ssrf_oob_confirmed_when_listener_hit():
    findings = probe_ssrf(
        "http://127.0.0.1/fetch",
        "GET",
        [{"name": "url", "value": "http://example.com"}],
        "session=owner",
        client=FakeClient(lambda *a, **k: FakeResp(200, "ok")),
        pacer=Pacer(0),
        listen_fn=_listen_hit,
        oob_timeout=0,
    )
    hit = next(f for f in findings if f.id == "ssrf-oob")
    assert hit.confidence == "confirmed"
    assert hit.severity == "critical"
    assert hit.category == "payload"
    assert "127.0.0.1:54321/ssrf-" in (hit.evidence or "")


def test_ssrf_metadata_body_is_confirmed():
    def handler(method, url, kw):
        if any("169.254.169.254" in v for v in _values(kw)):
            return FakeResp(200, "instance-id\ni-abc\nami-id\nami-123")
        return FakeResp(200, "ok")

    findings = probe_ssrf(
        "http://127.0.0.1/proxy",
        "POST",
        [{"name": "callback"}],
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
        listen_fn=_listen_miss,
        oob_timeout=0,
    )
    hit = next(f for f in findings if f.id == "ssrf-oob")
    assert hit.confidence == "confirmed"
    assert "169.254.169.254" in (hit.evidence or "")


def test_ssrf_localhost_root_marker_is_confirmed():
    def handler(method, url, kw):
        if any(
            v.rstrip("/") == "http://localhost" or v == "http://localhost/"
            for v in _values(kw)
        ):
            return FakeResp(200, "root:x:0:0:root:/root:/bin/bash")
        return FakeResp(200, "ok")

    findings = probe_ssrf(
        "http://127.0.0.1/load",
        "GET",
        [{"name": "src"}],
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
        listen_fn=_listen_miss,
        oob_timeout=0,
    )
    hit = next(f for f in findings if f.id == "ssrf-oob")
    assert hit.severity == "critical"
    assert "localhost" in (hit.evidence or "")


def test_ssrf_reflected_heuristic_when_url_echoed():
    def handler(method, url, kw):
        values = _values(kw)
        if any("/ssrf-" in v for v in values):
            return FakeResp(200, f"fetching {values[0]}")
        return FakeResp(200, "ok")

    findings = probe_ssrf(
        "http://127.0.0.1/fetch",
        "GET",
        [{"name": "target"}],
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
        listen_fn=_listen_miss,
        oob_timeout=0,
    )
    hit = next(f for f in findings if f.id == "ssrf-reflected")
    assert hit.confidence == "heuristic"
    assert hit.severity == "high"


def test_ssrf_reflected_heuristic_on_unusual_timing():
    def handler(method, url, kw):
        if any("/ssrf-" in v for v in _values(kw)):
            return FakeResp(200, "ok", elapsed=3.0)
        return FakeResp(200, "ok", elapsed=0.1)

    findings = probe_ssrf(
        "http://127.0.0.1/fetch",
        "GET",
        [{"name": "webhook"}],
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
        listen_fn=_listen_miss,
        oob_timeout=0,
    )
    hit = next(f for f in findings if f.id == "ssrf-reflected")
    assert hit.confidence == "heuristic"
    assert "elapsed=" in (hit.evidence or "")


def test_ssrf_skips_non_matching_param_names():
    called = []

    def handler(method, url, kw):
        called.append(True)
        return FakeResp(200, "ok")

    findings = probe_ssrf(
        "http://127.0.0.1/search",
        "GET",
        [{"name": "q", "value": "test"}],
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
        listen_fn=_listen_hit,
        oob_timeout=0,
    )
    assert findings == []
    assert called == []


def test_ssrf_clean_response_is_not_a_finding():
    findings = probe_ssrf(
        "http://127.0.0.1/fetch",
        "GET",
        [{"name": "url"}],
        "",
        client=FakeClient(lambda *a, **k: FakeResp(200, "hello world")),
        pacer=Pacer(0),
        listen_fn=_listen_miss,
        oob_timeout=0,
    )
    assert findings == []


def test_ssrf_network_error_returns_empty():
    class Boom:
        def request(self, *a, **k):
            raise ConnectionError("down")

        def close(self):
            pass

    findings = probe_ssrf(
        "http://127.0.0.1/fetch",
        "GET",
        [{"name": "url"}],
        "",
        client=Boom(),
        pacer=Pacer(0),
        listen_fn=_listen_miss,
        oob_timeout=0,
    )
    assert findings == []


def test_ssrf_listen_factory_failure_fails_closed():
    def boom_listen(timeout: float):
        raise OSError("no bind")

    findings = probe_ssrf(
        "http://127.0.0.1/fetch",
        "GET",
        [{"name": "url"}],
        "",
        client=FakeClient(lambda *a, **k: FakeResp(200, "ok")),
        pacer=Pacer(0),
        listen_fn=boom_listen,
        oob_timeout=0,
    )
    assert not any(f.id == "ssrf-oob" for f in findings)
