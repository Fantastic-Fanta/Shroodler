from __future__ import annotations

import json

from shroodler.pacer import Pacer
from shroodler.program import ProgramState
from shroodler.second_account import (
    auto_register_peer,
    detect_registration_url,
    fill_register_params,
    peer_cookie_from_state,
)


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


class FakeConfig:
    def __init__(self, login_recipe=None, peer_cookie=None):
        self.login_recipe = login_recipe
        self.peer_cookie = peer_cookie


def test_detect_registration_url_from_post_signup():
    state = ProgramState(
        slug="lab",
        endpoints={
            "http://127.0.0.1/api/signup": {"method": "POST", "params": [{"name": "email"}]},
            "http://127.0.0.1/search": {"method": "GET"},
        },
    )
    assert detect_registration_url(state) == "http://127.0.0.1/api/signup"


def test_detect_registration_url_prefers_state_field():
    state = ProgramState(
        slug="lab",
        registration_url="http://127.0.0.1/join",
        endpoints={"http://127.0.0.1/api/signup": {"method": "POST"}},
    )
    assert detect_registration_url(state) == "http://127.0.0.1/join"


def test_fill_register_params_maps_user_and_password():
    filled = fill_register_params(
        [
            {"name": "email"},
            {"name": "password"},
            {"name": "confirm"},
            {"name": "tos"},
        ],
        "shroodler-peer-abcd@example.com",
        "Shroodler1!Peer",
    )
    assert filled["email"] == "shroodler-peer-abcd@example.com"
    assert filled["password"] == "Shroodler1!Peer"
    assert filled["confirm"] == "Shroodler1!Peer"
    assert filled["tos"] == "shroodler-test"


def test_auto_register_peer_stores_session_and_finding():
    def handler(method, url, kw):
        data = kw.get("data") or {}
        if "signup" in url:
            assert data.get("email", "").endswith("@example.com")
            assert data["password"] == "Shroodler1!Peer"
            return FakeResp(201, "ok")
        if "login" in url:
            return FakeResp(200, "ok", headers={"Set-Cookie": "session=peer-token; Path=/"})
        return FakeResp(404, "missing")

    state = ProgramState(
        slug="lab",
        endpoints={
            "http://127.0.0.1/register": {
                "method": "POST",
                "params": [{"name": "email"}, {"name": "password"}],
            },
            "http://127.0.0.1/login": {
                "method": "POST",
                "params": [{"name": "email"}, {"name": "password"}],
            },
        },
    )
    config = FakeConfig()
    findings = auto_register_peer(
        state,
        config,
        client=FakeClient(handler),
        pacer=Pacer(0),
        nonce="abcd",
    )
    hit = next(f for f in findings if f.id == "peer-account-registered")
    assert hit.severity == "info"
    assert hit.category == "scan-note"
    assert hit.confidence == "confirmed"
    assert state.peer_session == {"name": "session", "value": "peer-token"}
    assert config.peer_cookie == "session=peer-token"
    assert "shroodler-peer-abcd@example.com" in hit.description


def test_auto_register_peer_uses_register_cookie_if_login_missing():
    def handler(method, url, kw):
        return FakeResp(200, "ok", headers={"set-cookie": "sid=from-register"})

    state = ProgramState(
        slug="lab",
        endpoints={"http://127.0.0.1/signup": {"method": "POST", "params": [{"name": "user"}]}},
    )
    config = FakeConfig()
    findings = auto_register_peer(
        state, config, client=FakeClient(handler), pacer=Pacer(0)
    )
    assert findings[0].id == "peer-account-registered"
    assert config.peer_cookie == "sid=from-register"


def test_auto_register_skips_when_no_register_endpoint():
    state = ProgramState(slug="lab", endpoints={"http://127.0.0.1/search": {"method": "GET"}})
    config = FakeConfig()
    findings = auto_register_peer(state, config, client=FakeClient(lambda *a, **k: FakeResp()))
    assert findings == []
    assert config.peer_cookie is None


def test_auto_register_hydrates_existing_peer_session():
    state = ProgramState(slug="lab", peer_session={"name": "session", "value": "cached"})
    config = FakeConfig()
    called = []

    def handler(*a, **k):
        called.append(True)
        return FakeResp()

    findings = auto_register_peer(state, config, client=FakeClient(handler), pacer=Pacer(0))
    assert findings == []
    assert called == []
    assert config.peer_cookie == "session=cached"
    assert peer_cookie_from_state(state) == "session=cached"


def test_auto_register_network_error_returns_empty():
    class Boom:
        def request(self, *a, **k):
            raise ConnectionError("down")

        def close(self):
            pass

    state = ProgramState(
        slug="lab",
        endpoints={"http://127.0.0.1/register": {"method": "POST"}},
    )
    config = FakeConfig()
    findings = auto_register_peer(state, config, client=Boom(), pacer=Pacer(0))
    assert findings == []
    assert config.peer_cookie is None


def test_auto_register_uses_login_recipe_url(tmp_path):
    recipe = tmp_path / "login.json"
    recipe.write_text(
        json.dumps(
            {
                "url": "http://127.0.0.1/auth/login",
                "method": "POST",
                "fields": {"username": "owner", "password": "secret"},
            }
        ),
        encoding="utf-8",
    )
    seen = []

    def handler(method, url, kw):
        seen.append(url)
        if "login" in url:
            return FakeResp(200, "ok", headers={"Set-Cookie": "session=from-recipe"})
        return FakeResp(200, "ok")

    state = ProgramState(
        slug="lab",
        endpoints={
            "http://127.0.0.1/register": {
                "method": "POST",
                "params": [{"name": "email"}, {"name": "password"}],
            }
        },
    )
    config = FakeConfig(login_recipe=str(recipe))
    findings = auto_register_peer(
        state, config, client=FakeClient(handler), pacer=Pacer(0)
    )
    assert any("auth/login" in u for u in seen)
    assert findings[0].id == "peer-account-registered"
    assert config.peer_cookie == "session=from-recipe"
