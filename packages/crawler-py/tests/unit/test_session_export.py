from __future__ import annotations

import json

from shroodler.auth import CookieSpec
from shroodler.session_export import export_from_path, export_session, specs_to_storage_state


def test_specs_to_storage_state_filters_origin():
    specs = [
        CookieSpec(name="app", value="1", domain="app.example", http_only=True, secure=True),
        CookieSpec(name="other", value="2", domain="evil.test"),
    ]
    doc = specs_to_storage_state(specs, origin="https://app.example/")
    names = {c["name"] for c in doc["cookies"]}
    assert names == {"app"}
    assert doc["cookies"][0]["httpOnly"] is True


def test_export_from_storage_state_roundtrip(tmp_path):
    src = {
        "cookies": [
            {
                "name": "session",
                "value": "abc",
                "domain": "127.0.0.1",
                "path": "/",
                "httpOnly": True,
                "secure": False,
                "sameSite": "Lax",
            }
        ],
        "origins": [],
    }
    p = tmp_path / "in.json"
    p.write_text(json.dumps(src), encoding="utf-8")
    out = export_from_path(p, origin="http://127.0.0.1/")
    assert out["cookies"][0]["name"] == "session"
    assert out["cookies"][0]["value"] == "abc"


def test_export_from_cookie_pairs():
    doc = export_session(pairs=["session=abc", "pref=1"], origin="http://127.0.0.1/")
    names = {c["name"] for c in doc["cookies"]}
    assert names == {"session", "pref"}


def test_cdp_refuses_remote_without_allow_external():
    import pytest

    from shroodler.session_export import export_from_cdp

    with pytest.raises(ValueError, match="non-loopback|non-local"):
        export_from_cdp("https://evil.example:9222")
    with pytest.raises(ValueError, match="http"):
        export_from_cdp("ws://127.0.0.1:9222")
    with pytest.raises(ValueError, match="userinfo"):
        export_from_cdp("http://user:pass@127.0.0.1:9222")
    with pytest.raises(ValueError, match="non-loopback|non-local"):
        export_from_cdp("http://chrome.local:9222")
    with pytest.raises(ValueError, match="non-loopback|non-local"):
        export_from_cdp("http://0.0.0.0:9222")
    with pytest.raises(ValueError, match="hostname"):
        export_from_cdp("http://")
    with pytest.raises(ValueError, match="non-loopback|non-local"):
        export_from_cdp("http://localhost.localdomain:9222")


def test_origin_must_be_absolute_http_url():
    import pytest

    specs = [
        CookieSpec(name="app", value="1", domain="app.example"),
        CookieSpec(name="other", value="2", domain="evil.test"),
    ]
    with pytest.raises(ValueError, match="http"):
        specs_to_storage_state(specs, origin="app.example")
    with pytest.raises(ValueError, match="http"):
        specs_to_storage_state(specs, origin="https://")


def test_origin_filter_rejects_public_suffix_domain():
    specs = [
        CookieSpec(name="wide", value="1", domain="com"),
        CookieSpec(name="app", value="2", domain="app.example"),
    ]
    doc = specs_to_storage_state(specs, origin="https://app.example/")
    names = {c["name"] for c in doc["cookies"]}
    assert names == {"app"}


def test_crlf_cookie_values_are_dropped():
    specs = [
        CookieSpec(name="ok", value="abc", domain="127.0.0.1"),
        CookieSpec(name="bad", value="abc\r\nX-Injected: 1", domain="127.0.0.1"),
        CookieSpec(name="semi", value="a;b", domain="127.0.0.1"),
    ]
    doc = specs_to_storage_state(specs, origin="http://127.0.0.1/")
    names = {c["name"] for c in doc["cookies"]}
    assert names == {"ok"}


def test_cdp_refuses_redirect_and_foreign_websocket(monkeypatch):
    import pytest

    from shroodler.session_export import export_from_cdp

    class RedirectResp:
        status_code = 302

        def json(self):
            return {}

    class ForeignWsResp:
        status_code = 200

        def json(self):
            return {"webSocketDebuggerUrl": "ws://169.254.169.254:9222/devtools"}

    class FakeClient:
        payload = RedirectResp()

        def __init__(self, **_kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

        def get(self, _url):
            return self.payload

    monkeypatch.setattr("shroodler.session_export.httpx.Client", FakeClient)
    with pytest.raises(ValueError, match="redirect"):
        export_from_cdp("http://127.0.0.1:9222")
    FakeClient.payload = ForeignWsResp()
    with pytest.raises(ValueError, match="non-loopback|webSocketDebuggerUrl"):
        export_from_cdp("http://127.0.0.1:9222")

    class LocalPivotResp:
        status_code = 200

        def json(self):
            return {"webSocketDebuggerUrl": "ws://127.0.0.1:2375/devtools"}

    FakeClient.payload = LocalPivotResp()
    with pytest.raises(ValueError, match="port"):
        export_from_cdp("http://127.0.0.1:9222")


def test_export_from_netscape(tmp_path):
    p = tmp_path / "cookies.txt"
    p.write_text(
        "# Netscape\n"
        "127.0.0.1\tFALSE\t/\tFALSE\t0\tsession\tabc\n",
        encoding="utf-8",
    )
    out = export_from_path(p, origin="http://127.0.0.1/")
    assert out["cookies"][0]["name"] == "session"
    assert out["cookies"][0]["value"] == "abc"
