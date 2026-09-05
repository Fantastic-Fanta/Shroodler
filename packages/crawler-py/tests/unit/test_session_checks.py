from __future__ import annotations

import httpx

from shroodler.session_checks import (
    check_logout_invalidation,
    check_session_fixation,
    session_cookies,
)


def test_session_cookies_filters_to_session_like_names():
    client = httpx.Client()
    client.cookies.set("sessionid", "abc123")
    client.cookies.set("theme", "dark")
    client.cookies.set("JSESSIONID", "xyz")
    cookies = session_cookies(client)
    assert cookies == {"sessionid": "abc123", "JSESSIONID": "xyz"}
    client.close()


def test_check_session_fixation_flags_unchanged_value():
    findings = check_session_fixation(
        {"sessionid": "same-value"}, {"sessionid": "same-value"}, "http://127.0.0.1/"
    )
    assert len(findings) == 1
    assert findings[0].id == "session-fixation"
    assert findings[0].category == "auth"


def test_check_session_fixation_silent_when_regenerated():
    findings = check_session_fixation(
        {"sessionid": "old-value"}, {"sessionid": "new-value"}, "http://127.0.0.1/"
    )
    assert findings == []


def test_check_session_fixation_ignores_empty_pre_value():
    findings = check_session_fixation({"sessionid": ""}, {"sessionid": ""}, "http://127.0.0.1/")
    assert findings == []


def test_check_session_fixation_no_pre_cookies_no_findings():
    assert check_session_fixation({}, {"sessionid": "new"}, "http://127.0.0.1/") == []


def test_check_logout_invalidation_no_stale_cookie_returns_empty():
    assert check_logout_invalidation(
        logout_url="http://127.0.0.1/logout",
        logout_method="GET",
        protected_url="http://127.0.0.1/account",
        stale_cookie_header="",
    ) == []


def test_check_logout_invalidation_flags_still_accessible(fx):
    fx.on("GET", "/logout", lambda inc: (204, {}, b""))
    fx.on(
        "GET",
        "/account",
        lambda inc: (200, {}, b"secret account page"),
    )
    findings = check_logout_invalidation(
        logout_url=fx.origin + "/logout",
        logout_method="GET",
        protected_url=fx.origin + "/account",
        stale_cookie_header="sessionid=stale-value",
    )
    assert len(findings) == 1
    assert findings[0].id == "logout-session-not-invalidated"
    assert findings[0].category == "auth"


def test_check_logout_invalidation_silent_when_denied(fx):
    fx.on("GET", "/logout", lambda inc: (204, {}, b""))
    fx.on("GET", "/account", lambda inc: (403, {}, b"forbidden"))
    findings = check_logout_invalidation(
        logout_url=fx.origin + "/logout",
        logout_method="GET",
        protected_url=fx.origin + "/account",
        stale_cookie_header="sessionid=stale-value",
    )
    assert findings == []
