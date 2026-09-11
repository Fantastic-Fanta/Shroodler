"""Tests for SQL-injection authentication-bypass detection."""

from __future__ import annotations

from shroodler.pacer import Pacer
from shroodler.probes import auth_bypass as ab


class _Cookies:
    def __init__(self, names):
        self._n = set(names)

    def keys(self):
        return self._n


class Resp:
    def __init__(self, status=200, cookies=(), location="", body=""):
        self.status_code = status
        self.headers = {"location": location} if location else {}
        self.cookies = _Cookies(cookies)
        self.text = body
        self.content = body.encode()


LOGIN_PARAMS = [{"name": "uid"}, {"name": "passw"}, {"name": "btnSubmit", "value": "Login"}]


def _is_bypass(form):
    return any("'" in str(v) for v in form.values())


def test_bypass_flagged_on_new_cookie(monkeypatch):
    def req(method, url, *, data=None, **k):
        if _is_bypass(data or {}):
            return Resp(302, cookies=["JSESSIONID", "AltoroAccounts"], location="/bank/main.jsp")
        return Resp(302, cookies=["JSESSIONID"], location="login.jsp")

    monkeypatch.setattr(ab, "request", req)
    findings = ab.probe_auth_bypass("http://t/doLogin", "POST", LOGIN_PARAMS, "", pacer=Pacer(0))
    assert len(findings) == 1
    assert findings[0].id == "sqli-auth-bypass"
    assert findings[0].severity == "critical"


def test_bypass_flagged_on_redirect_divergence(monkeypatch):
    def req(method, url, *, data=None, **k):
        if _is_bypass(data or {}):
            return Resp(302, cookies=["JSESSIONID"], location="/dashboard")
        return Resp(302, cookies=["JSESSIONID"], location="/login")

    monkeypatch.setattr(ab, "request", req)
    findings = ab.probe_auth_bypass("http://t/doLogin", "POST", LOGIN_PARAMS, "", pacer=Pacer(0))
    assert findings and findings[0].id == "sqli-auth-bypass"


def test_no_finding_when_responses_identical(monkeypatch):
    monkeypatch.setattr(
        ab, "request", lambda *a, **k: Resp(302, cookies=["JSESSIONID"], location="/login")
    )
    assert ab.probe_auth_bypass("http://t/doLogin", "POST", LOGIN_PARAMS, "", pacer=Pacer(0)) == []


def test_skips_non_login_endpoint(monkeypatch):
    called = {"n": 0}

    def req(*a, **k):
        called["n"] += 1
        return Resp(200)

    monkeypatch.setattr(ab, "request", req)
    params = [{"name": "q"}, {"name": "page"}]
    assert ab.probe_auth_bypass("http://t/search", "POST", params, "") == []
    assert called["n"] == 0


def test_skips_get(monkeypatch):
    monkeypatch.setattr(ab, "request", lambda *a, **k: Resp(200))
    assert ab.probe_auth_bypass("http://t/doLogin", "GET", LOGIN_PARAMS, "") == []


def test_login_path_with_identity_field_no_password(monkeypatch):
    # A login-ish path with a username field but no password field still probes.
    def req(method, url, *, data=None, **k):
        if _is_bypass(data or {}):
            return Resp(200, body="Welcome back")
        return Resp(200, body="Login failed: invalid")

    monkeypatch.setattr(ab, "request", req)
    findings = ab.probe_auth_bypass(
        "http://t/login", "POST", [{"name": "user"}], "", pacer=Pacer(0)
    )
    assert findings and findings[0].id == "sqli-auth-bypass"
