from __future__ import annotations

import json

import httpx

from shroodler.login_executor import (
    LoginExecutor,
    LoginResult,
    apply_session,
    substitute_templates,
)
from shroodler.pacer import Pacer
from shroodler.probes.common import probe_http_session, request
from shroodler.program import ProgramState


def _executor(handler, pacer=None) -> LoginExecutor:
    return LoginExecutor(pacer=pacer or Pacer(0), transport=httpx.MockTransport(handler))


def test_form_login_extracts_cookies_and_headers():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            body = request.content.decode()
            assert "username=admin" in body
            assert "password=secret" in body
            return httpx.Response(
                200,
                json={"ok": True},
                headers={
                    "X-Session": "hdr-token",
                    "Set-Cookie": "sid=cookie-1; Path=/",
                },
            )
        return httpx.Response(404)

    result = _executor(handler).run_sync(
        {
            "url": "http://test.local/login",
            "method": "POST",
            "content_type": "form",
            "include_hidden": False,
            "fields": {"username": "admin", "password": "secret"},
            "extract": [{"header": "X-Session", "as": "x_session"}],
        }
    )
    assert result.success is True
    assert result.error is None
    assert result.inject_cookies.get("sid") == "cookie-1"
    assert result.extracted.get("x_session") == "hdr-token"


def test_json_login_extracts_dotted_access_token():
    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        assert payload == {"username": "admin", "password": "secret"}
        return httpx.Response(200, json={"data": {"token": "abc123"}})

    result = _executor(handler).run_sync(
        {
            "url": "http://test.local/api/login",
            "content_type": "json",
            "fields": {"username": "admin", "password": "secret"},
            "extract": [{"json": "data.token", "as": "access_token"}],
        }
    )
    assert result.success is True
    assert result.extracted["access_token"] == "abc123"
    assert result.inject_headers["Authorization"] == "Bearer abc123"


def test_template_substitution_from_env(monkeypatch):
    monkeypatch.setenv("LOGIN_USER", "alice")
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = request.content.decode()
        return httpx.Response(200, json={"ok": True})

    result = _executor(handler).run_sync(
        {
            "url": "http://test.local/login",
            "content_type": "json",
            "fields": {"username": "{{LOGIN_USER}}", "password": "x"},
        }
    )
    assert result.success is True
    assert json.loads(seen["body"])["username"] == "alice"


def test_template_substitution_from_credentials_beats_env(monkeypatch):
    monkeypatch.setenv("PASS", "from-env")
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = request.content.decode()
        return httpx.Response(200, json={"ok": True})

    result = _executor(handler).run_sync(
        {
            "url": "http://test.local/login",
            "content_type": "json",
            "credentials": {"PASS": "from-recipe"},
            "fields": {"password": "{{PASS}}"},
        }
    )
    assert result.success is True
    assert json.loads(seen["body"])["password"] == "from-recipe"


def test_cookie_extract():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"ok": True},
            headers={"Set-Cookie": "sessionid=sess-99; Path=/"},
        )

    result = _executor(handler).run_sync(
        {
            "url": "http://test.local/login",
            "content_type": "json",
            "fields": {"u": "a"},
            "extract": [{"cookie": "sessionid", "as": "sid"}],
        }
    )
    assert result.success is True
    assert result.extracted["sid"] == "sess-99"
    assert result.inject_cookies["sessionid"] == "sess-99"


def test_header_extract():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True}, headers={"X-CSRF-Token": "csrf-1"})

    result = _executor(handler).run_sync(
        {
            "url": "http://test.local/login",
            "content_type": "json",
            "fields": {"u": "a"},
            "extract": [{"header": "X-CSRF-Token", "as": "csrf"}],
        }
    )
    assert result.success is True
    assert result.extracted["csrf"] == "csrf-1"


def test_regex_extract():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text='<input name="csrf" value="tok_abc">')

    result = _executor(handler).run_sync(
        {
            "url": "http://test.local/login",
            "content_type": "form",
            "include_hidden": False,
            "fields": {"u": "a"},
            "extract": [{"regex": r'value="([^"]+)"', "as": "csrf"}],
        }
    )
    assert result.success is True
    assert result.extracted["csrf"] == "tok_abc"


def test_failed_login_401():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text="unauthorized")

    result = _executor(handler).run_sync(
        {
            "url": "http://test.local/login",
            "content_type": "json",
            "fields": {"u": "a"},
        }
    )
    assert result.success is False
    assert result.error
    assert "401" in result.error


def test_verify_success_and_failure():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/me":
            cookie = request.headers.get("cookie") or request.headers.get("Cookie") or ""
            if "sid=ok" in cookie:
                return httpx.Response(200, text="welcome alice")
            return httpx.Response(401, text="no")
        return httpx.Response(404)

    executor = _executor(handler)
    assert executor.verify_sync(
        "http://test.local/me",
        marker="alice",
        cookies={"sid": "ok"},
    )
    assert not executor.verify_sync("http://test.local/me", marker="alice")
    assert not executor.verify_sync(
        "http://test.local/me",
        marker="missing-marker",
        cookies={"sid": "ok"},
    )


def test_run_verify_url_must_match_marker():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/login"):
            return httpx.Response(
                200,
                json={"ok": True},
                headers={"Set-Cookie": "sid=ok; Path=/"},
            )
        if request.url.path.endswith("/me"):
            return httpx.Response(200, text="welcome alice")
        return httpx.Response(404)

    ok = _executor(handler).run_sync(
        {
            "url": "/login",
            "content_type": "json",
            "fields": {"u": "a"},
            "verify_url": "/me",
            "verify_marker": "alice",
        },
        seed="http://test.local/",
    )
    assert ok.success is True

    bad = _executor(handler).run_sync(
        {
            "url": "/login",
            "content_type": "json",
            "fields": {"u": "a"},
            "verify_url": "/me",
            "verify_marker": "not-present",
        },
        seed="http://test.local/",
    )
    assert bad.success is False
    assert bad.error == "login verify failed"


def test_apply_session_writes_program_state():
    state = ProgramState(slug="lab")
    apply_session(state, {"Authorization": "Bearer t"}, {"sid": "1"})
    assert state.login_headers["Authorization"] == "Bearer t"
    assert state.login_cookies["sid"] == "1"


def test_substitute_templates_plain():
    assert substitute_templates("{{A}}-{{B}}", {"A": "1"}, {"B": "2"}) == "1-2"
    assert "{{MISSING}}" in substitute_templates("{{MISSING}}", {}, {})


def test_request_reauth_on_401_retries_once():
    calls = {"n": 0, "reauth": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(401, text="expired")
        return httpx.Response(200, text="ok")

    def reauth() -> bool:
        calls["reauth"] += 1
        return True

    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        resp = request(
            "GET",
            "http://test.local/api",
            client=client,
            pacer=Pacer(0),
            reauth=reauth,
        )
    finally:
        client.close()
    assert resp is not None
    assert resp.status_code == 200
    assert calls["reauth"] == 1
    assert calls["n"] == 2


def test_request_reauth_does_not_loop():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(403, text="no")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        resp = request(
            "GET",
            "http://test.local/api",
            client=client,
            pacer=Pacer(0),
            reauth=lambda: True,
        )
    finally:
        client.close()
    assert resp is not None
    assert resp.status_code == 403
    assert calls["n"] == 2


def test_request_extra_cookies_and_headers():
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["cookie"] = request.headers.get("cookie") or ""
        seen["auth"] = request.headers.get("authorization") or ""
        return httpx.Response(200, text="ok")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        request(
            "GET",
            "http://test.local/api",
            cookie_header="a=1",
            extra_headers={"Authorization": "Bearer z"},
            extra_cookies={"b": "2"},
            client=client,
            pacer=Pacer(0),
        )
    finally:
        client.close()
    assert "a=1" in seen["cookie"] or "b=2" in seen["cookie"]
    assert "Bearer z" in seen["auth"]


def test_probe_session_does_not_attach_owner_creds_to_peer():
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("authorization") or "")
        return httpx.Response(200, text="ok")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        with probe_http_session(
            extra_headers={"Authorization": "Bearer owner"},
            extra_cookies={"sid": "owner"},
            owner_cookie_header="sid=owner",
        ):
            request(
                "GET",
                "http://test.local/api",
                cookie_header="sid=owner",
                client=client,
                pacer=Pacer(0),
            )
            request(
                "GET",
                "http://test.local/api",
                cookie_header="sid=peer",
                client=client,
                pacer=Pacer(0),
            )
    finally:
        client.close()
    assert seen[0] == "Bearer owner"
    assert seen[1] == ""


def test_login_result_defaults():
    row = LoginResult(success=False, inject_headers={}, inject_cookies={}, extracted={})
    assert row.error is None
