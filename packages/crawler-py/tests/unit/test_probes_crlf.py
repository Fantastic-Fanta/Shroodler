from __future__ import annotations

from shroodler.pacer import Pacer
from shroodler.probes.crlf import probe_crlf


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


def test_crlf_header_injection_from_param():
    def handler(method, url, kw):
        for value in _values(kw):
            if "X-Injected:" in value or "%0d%0aX-Injected" in value:
                nonce = value.split("shroodler-")[-1]
                return FakeResp(200, "ok", headers={"X-Injected": f"shroodler-{nonce}"})
        return FakeResp(200, "ok")

    findings = probe_crlf(
        "http://127.0.0.1/search",
        "GET",
        [{"name": "q", "value": "x"}],
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    hit = next(f for f in findings if f.id == "crlf-header-injection")
    assert hit.severity == "high"
    assert hit.confidence == "confirmed"
    assert hit.category == "payload"


def test_crlf_set_cookie_from_path():
    def handler(method, url, kw):
        if "Set-Cookie:" in url or "%0d%0aSet-Cookie" in url:
            nonce = url.rsplit("shroodler=", 1)[-1]
            return FakeResp(200, "ok", headers={"Set-Cookie": f"shroodler={nonce}"})
        return FakeResp(200, "ok")

    findings = probe_crlf(
        "http://127.0.0.1/page",
        "GET",
        [],
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    hit = next(f for f in findings if f.id == "crlf-header-injection")
    assert "set-cookie=" in (hit.evidence or "").lower() or "nonce=" in (hit.evidence or "")


def test_crlf_response_splitting_on_login_location():
    def handler(method, url, kw):
        for value in _values(kw):
            if "X-Injected:" in value or "%0d%0aX-Injected" in value:
                nonce = value.split("shroodler-")[-1]
                return FakeResp(
                    302,
                    "",
                    headers={"Location": f"/home\r\nX-Injected: shroodler-{nonce}"},
                )
        return FakeResp(302, "", headers={"Location": "/home"})

    findings = probe_crlf(
        "http://127.0.0.1/login",
        "GET",
        [{"name": "next"}],
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    hit = next(f for f in findings if f.id == "crlf-response-splitting")
    assert hit.severity == "high"
    assert hit.confidence == "confirmed"


def test_crlf_no_finding_on_clean_response():
    findings = probe_crlf(
        "http://127.0.0.1/search",
        "GET",
        [{"name": "q"}],
        "",
        client=FakeClient(lambda *a, **k: FakeResp(200, "ok")),
        pacer=Pacer(0),
    )
    assert findings == []
