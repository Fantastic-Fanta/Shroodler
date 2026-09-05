from __future__ import annotations

import json

from shroodler.crawler import crawl_url


def test_flags_session_fixation_when_cookie_unchanged_by_login(fx, tmp_path):
    def home(req):
        headers = {"Content-Type": "text/html; charset=utf-8"}
        if "sessionid=" not in req.cookies:
            headers["Set-Cookie"] = "sessionid=fixed-value-123; Path=/"
        return 200, headers, b'<a href="/secret">s</a>'

    def login(req):
        if req.method == "GET":
            body = b'<form method="POST" action="/login"><input name="user"></form>'
            return 200, {"Content-Type": "text/html; charset=utf-8"}, body
        # Vulnerable: login succeeds but does NOT rotate the session cookie.
        return 302, {"Location": "/"}, b""

    fx.on("GET", "/", home)
    fx.on("GET", "/login", login)
    fx.on("POST", "/login", login)
    fx.on("GET", "/secret", lambda req: (200, {}, b"<p>secret</p>"))

    recipe = tmp_path / "recipe.json"
    recipe_body = {"url": fx.origin + "/login", "fields": {"user": "ok"}}
    recipe.write_text(json.dumps(recipe_body), encoding="utf-8")

    result = crawl_url(fx.origin + "/", depth=1, ignore_robots=True, login_recipe=str(recipe))
    ids = {f.id for f in result.findings}
    assert "session-fixation" in ids


def test_no_session_fixation_when_login_rotates_cookie(fx, tmp_path):
    def home(req):
        headers = {"Content-Type": "text/html; charset=utf-8"}
        if "sessionid=" not in req.cookies:
            headers["Set-Cookie"] = "sessionid=pre-auth-value; Path=/"
        return 200, headers, b'<a href="/secret">s</a>'

    def login(req):
        if req.method == "GET":
            body = b'<form method="POST" action="/login"><input name="user"></form>'
            return 200, {"Content-Type": "text/html; charset=utf-8"}, body
        # Safe: login response rotates the session id.
        return 302, {"Location": "/", "Set-Cookie": "sessionid=post-auth-rotated; Path=/"}, b""

    fx.on("GET", "/", home)
    fx.on("GET", "/login", login)
    fx.on("POST", "/login", login)
    fx.on("GET", "/secret", lambda req: (200, {}, b"<p>secret</p>"))

    recipe = tmp_path / "recipe.json"
    recipe_body = {"url": fx.origin + "/login", "fields": {"user": "ok"}}
    recipe.write_text(json.dumps(recipe_body), encoding="utf-8")

    result = crawl_url(fx.origin + "/", depth=1, ignore_robots=True, login_recipe=str(recipe))
    ids = {f.id for f in result.findings}
    assert "session-fixation" not in ids


def test_flags_logout_not_invalidating_session(fx, tmp_path):
    def home(req):
        headers = {"Content-Type": "text/html; charset=utf-8"}
        if "sessionid=" not in req.cookies:
            headers["Set-Cookie"] = "sessionid=pre-auth; Path=/"
        return 200, headers, b'<a href="/secret">s</a>'

    def login(req):
        if req.method == "GET":
            body = b'<form method="POST" action="/login"><input name="user"></form>'
            return 200, {"Content-Type": "text/html; charset=utf-8"}, body
        return 302, {"Location": "/", "Set-Cookie": "sessionid=post-auth; Path=/"}, b""

    fx.on("GET", "/", home)
    fx.on("GET", "/login", login)
    fx.on("POST", "/login", login)
    fx.on("GET", "/secret", lambda req: (200, {}, b"<p>secret</p>"))
    # Logout "succeeds" but the app never actually revokes the session server-side.
    fx.on("GET", "/logout", lambda req: (204, {}, b""))
    fx.on("GET", "/account", lambda req: (200, {}, b"<p>still logged in</p>"))

    recipe = tmp_path / "recipe.json"
    recipe.write_text(
        json.dumps(
            {
                "url": fx.origin + "/login",
                "fields": {"user": "ok"},
                "logout_url": fx.origin + "/logout",
                "protected_url": fx.origin + "/account",
            }
        ),
        encoding="utf-8",
    )

    result = crawl_url(fx.origin + "/", depth=1, ignore_robots=True, login_recipe=str(recipe))
    ids = {f.id for f in result.findings}
    assert "logout-session-not-invalidated" in ids


def test_no_logout_finding_when_session_actually_invalidated(fx, tmp_path):
    def home(req):
        headers = {"Content-Type": "text/html; charset=utf-8"}
        if "sessionid=" not in req.cookies:
            headers["Set-Cookie"] = "sessionid=pre-auth; Path=/"
        return 200, headers, b'<a href="/secret">s</a>'

    def login(req):
        if req.method == "GET":
            body = b'<form method="POST" action="/login"><input name="user"></form>'
            return 200, {"Content-Type": "text/html; charset=utf-8"}, body
        return 302, {"Location": "/", "Set-Cookie": "sessionid=post-auth; Path=/"}, b""

    fx.on("GET", "/", home)
    fx.on("GET", "/login", login)
    fx.on("POST", "/login", login)
    fx.on("GET", "/secret", lambda req: (200, {}, b"<p>secret</p>"))
    fx.on("GET", "/logout", lambda req: (204, {}, b""))
    # Properly invalidated: the stale session now gets rejected.
    fx.on("GET", "/account", lambda req: (403, {}, b"forbidden"))

    recipe = tmp_path / "recipe.json"
    recipe.write_text(
        json.dumps(
            {
                "url": fx.origin + "/login",
                "fields": {"user": "ok"},
                "logout_url": fx.origin + "/logout",
                "protected_url": fx.origin + "/account",
            }
        ),
        encoding="utf-8",
    )

    result = crawl_url(fx.origin + "/", depth=1, ignore_robots=True, login_recipe=str(recipe))
    ids = {f.id for f in result.findings}
    assert "logout-session-not-invalidated" not in ids
