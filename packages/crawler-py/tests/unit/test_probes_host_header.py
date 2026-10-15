from __future__ import annotations

from shroodler.pacer import Pacer
from shroodler.probes.host_header import probe_host_header


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


def test_host_header_body_only_reflection_is_medium():
    # Reflected into the body (no redirect): a Host-trust misconfig that needs
    # an amplifier to hit a third party, so medium, not high.
    def handler(method, url, kw):
        headers = kw.get("headers") or {}
        if headers.get("Host") == "evil.example.com":
            return FakeResp(200, "welcome to evil.example.com")
        return FakeResp(200, "ok")

    client = FakeClient(handler)
    findings = probe_host_header(
        "http://127.0.0.1/app",
        "session=owner",
        client=client,
        pacer=Pacer(0),
    )
    hit = next(f for f in findings if f.id == "host-header-injection")
    assert hit.confidence == "confirmed"
    assert hit.severity == "medium"
    assert hit.category == "payload"
    assert "where=body" in (hit.evidence or "")
    assert any((c[2].get("headers") or {}).get("Host") == "evil.example.com" for c in client.calls)


def test_host_header_redirect_location_is_high():
    # Reflected into a redirect Location: the Host drives the redirect target,
    # directly abusable, so high.
    def handler(method, url, kw):
        headers = kw.get("headers") or {}
        if headers.get("X-Forwarded-Host") == "evil.example.com":
            return FakeResp(
                302,
                "ok",
                headers={"Location": "https://evil.example.com/login"},
            )
        return FakeResp(200, "ok")

    findings = probe_host_header(
        "http://app.internal/",
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    hit = next(f for f in findings if f.id == "host-header-injection")
    assert hit.severity == "high"
    assert "where=location" in (hit.evidence or "")
    assert "redirect=true" in (hit.evidence or "")
    assert "X-Forwarded-Host" in (hit.evidence or "")
    assert "evil.example.com" in (hit.evidence or "")


def test_host_header_location_without_redirect_is_medium():
    # Evil host echoed into a Location header on a 200 (not a 3xx): not a
    # redirect the attacker can drive, so medium.
    def handler(method, url, kw):
        headers = kw.get("headers") or {}
        if headers.get("Host") == "evil.example.com":
            return FakeResp(200, "ok", headers={"Location": "https://evil.example.com/x"})
        return FakeResp(200, "ok")

    findings = probe_host_header(
        "http://127.0.0.1/",
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    hit = next(f for f in findings if f.id == "host-header-injection")
    assert hit.severity == "medium"
    assert "redirect=false" in (hit.evidence or "")


def test_host_header_tries_x_host():
    def handler(method, url, kw):
        headers = kw.get("headers") or {}
        if headers.get("X-Host") == "evil.example.com":
            return FakeResp(200, "host=evil.example.com")
        return FakeResp(200, "ok")

    findings = probe_host_header(
        "http://127.0.0.1/",
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    assert any(f.id == "host-header-injection" for f in findings)


def test_host_header_clean_response_is_not_a_finding():
    findings = probe_host_header(
        "http://127.0.0.1/",
        "",
        client=FakeClient(lambda *a, **k: FakeResp(200, "hello world")),
        pacer=Pacer(0),
    )
    assert findings == []


def test_host_header_network_error_returns_empty():
    class Boom:
        def request(self, *a, **k):
            raise ConnectionError("down")

        def close(self):
            pass

    findings = probe_host_header(
        "http://127.0.0.1/",
        "",
        client=Boom(),
        pacer=Pacer(0),
    )
    assert findings == []
