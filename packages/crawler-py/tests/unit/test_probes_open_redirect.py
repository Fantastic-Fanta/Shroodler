from __future__ import annotations

from shroodler.pacer import Pacer
from shroodler.probes.open_redirect import probe_open_redirect


class FakeResp:
    def __init__(self, status=200, text="", headers=None):
        self.status_code = status
        self.text = text
        self.content = text.encode()
        self.headers = headers or {}


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


def test_open_redirect_confirmed_on_absolute_location():
    def handler(method, url, kw):
        values = _values(kw)
        if any("evil.example.com" in v for v in values):
            return FakeResp(
                302,
                "",
                headers={"Location": "https://evil.example.com/shroodler-redirect-abc"},
            )
        return FakeResp(200, "ok")

    findings = probe_open_redirect(
        "http://127.0.0.1/out",
        "GET",
        [{"name": "next", "value": "/home"}],
        "session=owner",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    hit = next(f for f in findings if f.id == "open-redirect")
    assert hit.confidence == "confirmed"
    assert hit.severity == "medium"
    assert hit.category == "payload"
    assert "evil.example.com" in (hit.evidence or "")


def test_open_redirect_confirmed_on_protocol_relative():
    def handler(method, url, kw):
        values = _values(kw)
        if any(v.startswith("//evil.example.com") for v in values):
            return FakeResp(301, "", headers={"location": "//evil.example.com/phish"})
        return FakeResp(200, "ok")

    findings = probe_open_redirect(
        "http://127.0.0.1/go",
        "GET",
        [{"name": "redirect"}],
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    hit = next(f for f in findings if f.id == "open-redirect")
    assert hit.severity == "medium"


def test_open_redirect_confirmed_on_backslash_payload():
    def handler(method, url, kw):
        values = _values(kw)
        if any("evil.example.com" in v and v.startswith("/\\") for v in values):
            return FakeResp(302, "", headers={"Location": "/\\evil.example.com"})
        return FakeResp(200, "ok")

    findings = probe_open_redirect(
        "http://127.0.0.1/out",
        "POST",
        [{"name": "url"}],
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    assert any(f.id == "open-redirect" for f in findings)


def test_open_redirect_probes_all_params_on_login_url():
    def handler(method, url, kw):
        values = _values(kw)
        if any("evil.example.com" in v for v in values):
            return FakeResp(302, "", headers={"Location": "https://evil.example.com/"})
        return FakeResp(200, "ok")

    findings = probe_open_redirect(
        "http://127.0.0.1/oauth/callback",
        "GET",
        [{"name": "foo", "value": "1"}],
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    assert any(f.id == "open-redirect" for f in findings)


def test_open_redirect_skips_unrelated_params():
    called = []

    def handler(method, url, kw):
        called.append(True)
        return FakeResp(302, "", headers={"Location": "https://evil.example.com/"})

    findings = probe_open_redirect(
        "http://127.0.0.1/search",
        "GET",
        [{"name": "q"}],
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    assert findings == []
    assert called == []


def test_open_redirect_200_with_evil_body_is_not_a_finding():
    findings = probe_open_redirect(
        "http://127.0.0.1/out",
        "GET",
        [{"name": "next"}],
        "",
        client=FakeClient(
            lambda *a, **k: FakeResp(200, "go to https://evil.example.com/")
        ),
        pacer=Pacer(0),
    )
    assert findings == []


def test_open_redirect_network_error_returns_empty():
    class Boom:
        def request(self, *a, **k):
            raise ConnectionError("down")

        def close(self):
            pass

    findings = probe_open_redirect(
        "http://127.0.0.1/out",
        "GET",
        [{"name": "next"}],
        "",
        client=Boom(),
        pacer=Pacer(0),
    )
    assert findings == []
