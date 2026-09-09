from __future__ import annotations

from shroodler.pacer import Pacer
from shroodler.probes.websocket import discover_websocket_urls, probe_websocket


class FakeWS:
    def __init__(self, replies):
        self.replies = list(replies)
        self.sent = []
        self.closed = False

    def send(self, data):
        self.sent.append(data)

    def recv(self):
        return self.replies.pop(0) if self.replies else ""

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def test_discover_from_js_and_upgrade():
    js = """
    const a = new WebSocket("wss://example.com/ws");
    io("/socket.io");
    socket.connect("ws://example.com/sock");
    """
    urls = discover_websocket_urls(
        js,
        base_url="https://example.com/",
        captured_headers=[{"url": "wss://example.com/live", "headers": {"Upgrade": "websocket"}}],
    )
    assert "wss://example.com/ws" in urls
    assert "https://example.com/socket.io" in urls or "wss://example.com/socket.io" in urls
    assert "ws://example.com/sock" in urls
    assert "wss://example.com/live" in urls


def test_websocket_reflection_and_missing_auth():
    sockets = []

    def connector(url, headers):
        ws = FakeWS(['{"id":"shroodler-PLACE"}', '{"shroodlerPP":"x"}'])
        sockets.append((url, headers, ws))
        return ws

    # Capture nonce by echoing whatever was sent.
    def connector_echo(url, headers):
        ws = FakeWS([])

        def recv():
            last = ws.sent[-1] if ws.sent else ""
            return last

        ws.recv = recv  # type: ignore[method-assign]
        sockets.append(headers)
        return ws

    findings, discovered = probe_websocket(
        "ws://127.0.0.1/ws",
        "session=owner",
        connector=connector_echo,
        pacer=Pacer(0),
    )
    ids = {f.id for f in findings}
    assert "websocket-reflection" in ids
    assert "websocket-prototype-pollution" in ids
    assert "websocket-missing-auth" in ids
    reflect = next(f for f in findings if f.id == "websocket-reflection")
    assert reflect.severity == "low"
    assert reflect.confidence == "confirmed"
    missing = next(f for f in findings if f.id == "websocket-missing-auth")
    assert missing.severity == "high"
    assert missing.category == "auth"
    assert "ws://127.0.0.1/ws" in discovered


def test_websocket_skips_when_connect_unavailable():
    findings, _discovered = probe_websocket(
        "ws://127.0.0.1/ws",
        "session=owner",
        connector=lambda url, headers: (_ for _ in ()).throw(RuntimeError("no ws")),
        pacer=Pacer(0),
    )
    assert findings == []
