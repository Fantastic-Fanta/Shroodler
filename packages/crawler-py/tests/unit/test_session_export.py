from __future__ import annotations

import json

from shroodler.session_export import export_from_path, export_session, specs_to_storage_state
from shroodler.auth import CookieSpec


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
