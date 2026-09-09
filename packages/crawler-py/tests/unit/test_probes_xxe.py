from __future__ import annotations

from shroodler.pacer import Pacer
from shroodler.probes.xxe import probe_xxe


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


def _body(kw) -> str:
    content = kw.get("content")
    if isinstance(content, bytes):
        return content.decode("utf-8", errors="replace")
    if content:
        return str(content)
    files = kw.get("files") or {}
    if isinstance(files, dict):
        for value in files.values():
            if isinstance(value, tuple) and len(value) >= 2:
                data = value[1]
                if isinstance(data, bytes):
                    return data.decode("utf-8", errors="replace")
                return str(data)
    return ""


def _listen_hit(timeout: float):
    return 54321, lambda: True


def _listen_miss(timeout: float):
    return 54321, lambda: False


def test_xxe_oob_confirmed_when_listener_hit():
    findings = probe_xxe(
        "http://127.0.0.1/xml",
        "POST",
        [],
        "session=owner",
        client=FakeClient(lambda *a, **k: FakeResp(200, "ok")),
        pacer=Pacer(0),
        listen_fn=_listen_hit,
        oob_timeout=0,
        content_type="application/xml",
    )
    hit = next(f for f in findings if f.id == "xxe-oob")
    assert hit.severity == "critical"
    assert hit.confidence == "confirmed"
    assert hit.category == "payload"
    assert "nonce=" in (hit.evidence or "")


def test_xxe_file_read_passwd_marker():
    def handler(method, url, kw):
        body = _body(kw)
        if "file:///etc/passwd" in body:
            return FakeResp(200, "root:x:0:0:root:/root:/bin/bash")
        return FakeResp(200, "ok")

    findings = probe_xxe(
        "http://127.0.0.1/xml",
        "POST",
        [],
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
        listen_fn=_listen_miss,
        oob_timeout=0,
        content_type="text/xml",
    )
    hit = next(f for f in findings if f.id == "xxe-file-read")
    assert hit.confidence == "confirmed"
    assert hit.severity == "critical"
    assert "etc/passwd" in (hit.evidence or "")


def test_xxe_file_read_daemon_marker():
    def handler(method, url, kw):
        if "file:///etc/passwd" in _body(kw):
            return FakeResp(200, "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin")
        return FakeResp(200, "ok")

    findings = probe_xxe(
        "http://127.0.0.1/xml",
        "POST",
        [],
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
        listen_fn=_listen_miss,
        oob_timeout=0,
        content_type="application/xml",
    )
    assert any(f.id == "xxe-file-read" for f in findings)


def test_xxe_multipart_upload():
    def handler(method, url, kw):
        if "file:///etc/passwd" in _body(kw):
            return FakeResp(200, "root:x:0:0")
        return FakeResp(200, "ok")

    findings = probe_xxe(
        "http://127.0.0.1/upload",
        "POST",
        [{"name": "upload", "in": "file"}],
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
        listen_fn=_listen_miss,
        oob_timeout=0,
        content_type="multipart/form-data",
    )
    hit = next(f for f in findings if f.id == "xxe-file-read")
    assert "param=upload" in (hit.evidence or "")


def test_xxe_skips_json_content_type_without_file_param():
    called = []

    def handler(method, url, kw):
        called.append(True)
        return FakeResp(200, "ok")

    findings = probe_xxe(
        "http://127.0.0.1/api",
        "POST",
        [{"name": "q"}],
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
        listen_fn=_listen_hit,
        oob_timeout=0,
        content_type="application/json",
    )
    assert findings == []
    assert called == []


def test_xxe_unknown_content_type_skips_on_415():
    def handler(method, url, kw):
        return FakeResp(415, "unsupported")

    findings = probe_xxe(
        "http://127.0.0.1/submit",
        "POST",
        [],
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
        listen_fn=_listen_miss,
        oob_timeout=0,
        content_type="",
    )
    assert findings == []


def test_xxe_network_error_returns_empty():
    class Boom:
        def request(self, *a, **k):
            raise ConnectionError("down")

        def close(self):
            pass

    findings = probe_xxe(
        "http://127.0.0.1/xml",
        "POST",
        [],
        "",
        client=Boom(),
        pacer=Pacer(0),
        listen_fn=_listen_miss,
        oob_timeout=0,
        content_type="application/xml",
    )
    assert findings == []


def test_xxe_listen_factory_failure_fails_closed():
    def boom_listen(timeout: float):
        raise OSError("no bind")

    def handler(method, url, kw):
        if "file:///etc/passwd" in _body(kw):
            return FakeResp(200, "ok")
        return FakeResp(200, "ok")

    findings = probe_xxe(
        "http://127.0.0.1/xml",
        "POST",
        [],
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
        listen_fn=boom_listen,
        oob_timeout=0,
        content_type="application/xml",
    )
    assert not any(f.id == "xxe-oob" for f in findings)
