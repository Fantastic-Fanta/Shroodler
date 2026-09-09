from __future__ import annotations

import re

from shroodler.pacer import Pacer
from shroodler.probes.ssti import probe_ssti


class FakeResp:
    def __init__(self, status=200, text=""):
        self.status_code = status
        self.text = text
        self.content = text.encode()
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


_NONCE_RE = re.compile(r"\{\{(\d+)\*7\}\}")


def test_ssti_nonce_prime_is_confirmed():
    def handler(method, url, kw):
        for value in _values(kw):
            match = _NONCE_RE.search(value)
            if match:
                return FakeResp(200, f"result={int(match.group(1)) * 7}")
        return FakeResp(200, "hello")

    findings = probe_ssti(
        "http://127.0.0.1/search",
        "GET",
        [{"name": "q", "value": "test"}],
        "session=owner",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    hit = findings[0]
    assert hit.id == "ssti-reflected"
    assert hit.severity == "critical"
    assert hit.confidence == "confirmed"
    assert hit.category == "payload"
    assert "nonce=" in (hit.evidence or "")


def test_ssti_jinja_repeat_is_confirmed():
    def handler(method, url, kw):
        if any("{{7*'7'}}" in v for v in _values(kw)):
            return FakeResp(200, "x" + ("7" * 7) + "x")
        return FakeResp(200, "hello")

    findings = probe_ssti(
        "http://127.0.0.1/search",
        "POST",
        [{"name": "name"}],
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    hit = next(f for f in findings if f.id == "ssti-reflected")
    assert hit.confidence == "confirmed"
    assert "{{7*'7'}}" in (hit.evidence or "")


def test_ssti_freemarker_is_confirmed():
    def handler(method, url, kw):
        if any("freemarker" in v for v in _values(kw)):
            return FakeResp(200, "engine=FREEMARKER")
        return FakeResp(200, "hello")

    findings = probe_ssti(
        "http://127.0.0.1/render",
        "GET",
        [{"name": "tpl"}],
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    hit = next(f for f in findings if f.id == "ssti-reflected")
    assert "FREEMARKER" in (hit.evidence or "")


def test_ssti_erb_math_is_confirmed():
    def handler(method, url, kw):
        if any("<%= 7*7 %>" in v for v in _values(kw)):
            return FakeResp(200, "n=49")
        return FakeResp(200, "hello")

    findings = probe_ssti(
        "http://127.0.0.1/erb",
        "GET",
        [{"name": "q"}],
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    hit = next(f for f in findings if f.id == "ssti-reflected")
    assert hit.severity == "critical"


def test_ssti_skips_when_no_params():
    called = []

    def handler(method, url, kw):
        called.append(True)
        return FakeResp(200, "49")

    findings = probe_ssti(
        "http://127.0.0.1/search",
        "GET",
        [],
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    assert findings == []
    assert called == []


def test_ssti_cached_49_is_not_a_finding():
    findings = probe_ssti(
        "http://127.0.0.1/search",
        "GET",
        [{"name": "q"}],
        "",
        client=FakeClient(lambda *a, **k: FakeResp(200, "there are 49 items")),
        pacer=Pacer(0),
    )
    assert findings == []


def test_ssti_network_error_returns_empty():
    class Boom:
        def request(self, *a, **k):
            raise ConnectionError("down")

        def close(self):
            pass

    findings = probe_ssti(
        "http://127.0.0.1/search",
        "GET",
        [{"name": "q"}],
        "",
        client=Boom(),
        pacer=Pacer(0),
    )
    assert findings == []
