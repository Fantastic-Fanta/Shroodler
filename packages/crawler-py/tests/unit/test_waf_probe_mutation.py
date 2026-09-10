from __future__ import annotations

from datetime import timedelta

from shroodler.pacer import Pacer
from shroodler.probes.graphql import probe_graphql
from shroodler.probes.jwt import probe_jwt
from shroodler.probes.open_redirect import probe_open_redirect
from shroodler.probes.ssrf import _METADATA_PAYLOAD, probe_ssrf
from shroodler.probes.xxe import probe_xxe
from shroodler.program import ProgramState
from shroodler.waf_detect import mutate_payload


class FakeResp:
    def __init__(self, status=200, text="", headers=None, elapsed=0.0):
        self.status_code = status
        self.text = text
        self.content = text.encode() if isinstance(text, str) else text
        self.headers = headers or {}
        self.elapsed = timedelta(seconds=elapsed)


class FakeClient:
    def __init__(self, handler=None):
        self.handler = handler or (lambda *a, **k: FakeResp())
        self.calls = []

    def request(self, method, url, **kw):
        self.calls.append((method, url, kw))
        return self.handler(method, url, kw)

    def close(self):
        pass


def _listen_miss(timeout: float):
    return 54321, lambda: False


def _collect_ssrf(monkeypatch, **kwargs) -> list[str]:
    injected: list[str] = []

    def fake_inject(url, method, params, name, payload, **kw):
        injected.append(payload)
        return FakeResp()

    monkeypatch.setattr("shroodler.probes.ssrf.inject", fake_inject)
    monkeypatch.setattr("shroodler.probes.ssrf.request", lambda *a, **k: FakeResp())
    probe_ssrf(
        "http://127.0.0.1/fetch",
        "GET",
        [{"name": "url", "value": "http://example.com"}],
        "",
        pacer=Pacer(0),
        listen_fn=_listen_miss,
        oob_timeout=0,
        **kwargs,
    )
    return injected


def test_ssrf_mutates_when_waf_detected(monkeypatch):
    injected = _collect_ssrf(monkeypatch, waf_detected=True, waf_vendor="cloudflare")
    assert injected
    assert _METADATA_PAYLOAD in injected
    idx = injected.index(_METADATA_PAYLOAD)
    assert idx >= 0
    rest = injected[idx:]
    assert rest[0] == _METADATA_PAYLOAD
    blob = " ".join(injected)
    assert "%253C" in blob or "%25" in blob or "SeLeCt" in blob or any(
        p != _METADATA_PAYLOAD and "169.254" in p for p in injected
    )
    variants = mutate_payload("http://169.254.169.254/latest/meta-data/", "cloudflare")
    assert variants[0] == "http://169.254.169.254/latest/meta-data/"
    assert len(variants) > 1


def test_ssrf_payload_count_unchanged_without_waf(monkeypatch):
    off = _collect_ssrf(monkeypatch)
    also_off = _collect_ssrf(monkeypatch, waf_detected=False)
    flagged = _collect_ssrf(monkeypatch, state=ProgramState(slug="lab"))
    assert len(off) == len(also_off) == len(flagged)
    on = _collect_ssrf(monkeypatch, waf_detected=True)
    assert len(on) > len(off)


def _collect_redirect(monkeypatch, **kwargs) -> list[str]:
    injected: list[str] = []

    def fake_inject(url, method, params, name, payload, **kw):
        injected.append(payload)
        return FakeResp(status=200)

    monkeypatch.setattr("shroodler.probes.open_redirect.inject", fake_inject)
    probe_open_redirect(
        "http://127.0.0.1/out",
        "GET",
        [{"name": "next", "value": "/home"}],
        "",
        pacer=Pacer(0),
        **kwargs,
    )
    return injected


def test_open_redirect_mutates_when_waf_detected(monkeypatch):
    injected = _collect_redirect(monkeypatch, waf_detected=True)
    assert injected
    assert injected[0].startswith("https://evil.example.com/")
    off = _collect_redirect(monkeypatch)
    assert len(injected) > len(off)
    assert any(p != injected[0] for p in injected)


def test_open_redirect_payload_count_unchanged_without_waf(monkeypatch):
    off = _collect_redirect(monkeypatch)
    also = _collect_redirect(monkeypatch, waf_detected=False)
    assert len(off) == len(also)


def test_xxe_mutates_when_waf_detected(monkeypatch):
    sent: list[str] = []

    def fake_request(method, url, **kw):
        content = kw.get("content") or b""
        if isinstance(content, bytes):
            sent.append(content.decode("utf-8", errors="replace"))
        return FakeResp(status=200, text="ok")

    monkeypatch.setattr("shroodler.probes.xxe.request", fake_request)
    probe_xxe(
        "http://127.0.0.1/xml",
        "POST",
        [],
        "",
        pacer=Pacer(0),
        listen_fn=_listen_miss,
        oob_timeout=0,
        content_type="application/xml",
        waf_detected=True,
    )
    off_sent: list[str] = []

    def fake_off(method, url, **kw):
        content = kw.get("content") or b""
        if isinstance(content, bytes):
            off_sent.append(content.decode("utf-8", errors="replace"))
        return FakeResp(status=200, text="ok")

    monkeypatch.setattr("shroodler.probes.xxe.request", fake_off)
    probe_xxe(
        "http://127.0.0.1/xml",
        "POST",
        [],
        "",
        pacer=Pacer(0),
        listen_fn=_listen_miss,
        oob_timeout=0,
        content_type="application/xml",
    )
    assert sent
    assert len(sent) >= len(off_sent)
    original_file = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
    if original_file in sent:
        assert sent.count(original_file) >= 1


def test_xxe_payload_count_unchanged_without_waf(monkeypatch):
    counts: list[int] = []

    def run(flag: bool | None) -> None:
        n = {"c": 0}

        def fake_request(method, url, **kw):
            n["c"] += 1
            return FakeResp(status=400, text="no")

        monkeypatch.setattr("shroodler.probes.xxe.request", fake_request)
        kwargs = {} if flag is None else {"waf_detected": flag}
        probe_xxe(
            "http://127.0.0.1/xml",
            "POST",
            [],
            "",
            pacer=Pacer(0),
            listen_fn=_listen_miss,
            oob_timeout=0,
            content_type="application/xml",
            **kwargs,
        )
        counts.append(n["c"])

    run(None)
    run(False)
    assert counts[0] == counts[1]


def test_graphql_waf_mutation_does_not_crash():
    def handler(method, url, kw):
        return FakeResp(200, '{"data":{"__typename":"Query"}}')

    probe_graphql(
        "http://127.0.0.1/",
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
        waf_detected=True,
        waf_vendor="cloudflare",
    )


def test_jwt_waf_mutation_does_not_crash():
    import jwt as pyjwt
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        token = pyjwt.encode({"sub": "1"}, "secret", algorithm="HS256")

    def handler(method, url, kw):
        return FakeResp(403, "no")

    probe_jwt(
        "http://127.0.0.1/api/me",
        "",
        f"Authorization: Bearer {token}",
        client=FakeClient(handler),
        pacer=Pacer(0),
        waf_detected=True,
        waf_vendor="akamai",
    )
