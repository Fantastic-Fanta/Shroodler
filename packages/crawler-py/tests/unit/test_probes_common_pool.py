"""Tests for aggressive keep-alive client reuse in request()."""

from __future__ import annotations

from shroodler.probes.common import aggressive_client, request, use_aggressive_client


class _Resp:
    status_code = 200
    text = ""
    content = b""
    headers: dict = {}
    elapsed = 0.0


class RecordingClient:
    def __init__(self):
        self.calls = []
        self.closed = False

    def request(self, method, url, **kw):
        self.calls.append((method, url))
        return _Resp()

    def close(self):
        self.closed = True


def test_request_reuses_bound_aggressive_client():
    rc = RecordingClient()
    with use_aggressive_client(rc):
        request("GET", "http://t/a")
        request("GET", "http://t/b")
    # Both requests went through the one pooled client (keep-alive reuse)...
    assert rc.calls == [("GET", "http://t/a"), ("GET", "http://t/b")]
    # ...and request() must not close a client it did not create.
    assert rc.closed is False


def test_request_prefers_explicit_client_over_bound():
    explicit = RecordingClient()
    bound = RecordingClient()
    with use_aggressive_client(bound):
        request("GET", "http://t/x", client=explicit)
    assert explicit.calls == [("GET", "http://t/x")]
    assert bound.calls == []


def test_binding_resets_after_context():
    rc = RecordingClient()
    with use_aggressive_client(rc):
        pass
    # Outside the context, no pooled client is bound; a plain request builds its
    # own (real httpx) client and returns None on the unroutable host, no crash.
    assert request("GET", "http://127.0.0.1:9/none") is None


def test_aggressive_client_is_a_client():
    c = aggressive_client(timeout=2.0)
    try:
        assert hasattr(c, "request")
    finally:
        c.close()
