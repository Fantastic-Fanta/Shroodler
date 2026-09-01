from __future__ import annotations

import json
from urllib.parse import urlparse

from shroodler.auth import (
    cookies_from_json,
    cookies_from_netscape,
    load_cookie_jar,
    load_login_recipe,
    parse_cookie_pairs,
    parse_header_lines,
)
from shroodler.crawler import crawl_url


def test_parse_header_lines():
    parsed = parse_header_lines(["X-Lab-Auth: open", "X-Trace: a:b", "skip", " : empty-name"])
    assert parsed["X-Lab-Auth"] == "open"
    assert parsed["X-Trace"] == "a:b"
    assert "skip" not in parsed
    assert parse_header_lines(None) == {}


def test_parse_cookie_pairs_and_jars(tmp_path):
    assert parse_cookie_pairs(["auth=yes", "skip"])[0].name == "auth"
    netscape = tmp_path / "cookies.txt"
    netscape.write_text(
        "# Netscape HTTP Cookie File\n"
        "127.0.0.1\tFALSE\t/\tFALSE\t0\tauth\tyes\n",
        encoding="utf-8",
    )
    specs = load_cookie_jar(str(netscape), default_domain="127.0.0.1")
    assert specs[0].name == "auth" and specs[0].value == "yes"
    js = tmp_path / "cookies.json"
    js.write_text(
        json.dumps({"cookies": [{"name": "sid", "value": "1", "path": "/"}]}),
        encoding="utf-8",
    )
    assert load_cookie_jar(str(js))[0].name == "sid"
    assert cookies_from_json([{"name": "x", "value": "y"}])[0].value == "y"
    assert cookies_from_netscape("# only comment\n") == []


def test_load_login_recipe(tmp_path):
    p = tmp_path / "login.json"
    p.write_text(
        json.dumps({"url": "/login", "fields": {"username": "admin", "password": "admin"}}),
        encoding="utf-8",
    )
    recipe = load_login_recipe(str(p))
    assert recipe.url == "/login"
    assert recipe.fields["username"] == "admin"
    assert recipe.include_hidden is True


def test_cookie_jar_unlocks_gated_form(fx, tmp_path):
    fx.html("/", '<a href="/secret">s</a>')

    def secret(req):
        html = (
            b'<form action="/x" method="POST"><input name="secret_field"></form>'
            if "auth=yes" in req.cookies
            else b"<p>login wall</p>"
        )
        return 200, {"Content-Type": "text/html; charset=utf-8"}, html

    fx.on("GET", "/secret", secret)
    jar = tmp_path / "jar.json"
    jar.write_text(json.dumps([{"name": "auth", "value": "yes", "path": "/"}]), encoding="utf-8")
    anon = crawl_url(fx.origin + "/", depth=1, ignore_robots=True)
    authed = crawl_url(
        fx.origin + "/",
        depth=1,
        ignore_robots=True,
        cookie_jar=str(jar),
    )
    anon_names = {f.name for p in anon.pages for form in p.forms for f in form.fields}
    authed_names = {f.name for p in authed.pages for form in p.forms for f in form.fields}
    assert "secret_field" not in anon_names
    assert "secret_field" in authed_names


def test_cookie_flag_and_storage_state(fx, tmp_path):
    fx.html("/", '<a href="/secret">s</a>')

    def secret(req):
        html = (
            b'<form><input name="via_cookie"></form>'
            if "tok=abc" in req.cookies
            else b"<p>no</p>"
        )
        return 200, {"Content-Type": "text/html; charset=utf-8"}, html

    fx.on("GET", "/secret", secret)
    state = tmp_path / "state.json"
    state.write_text(
        json.dumps({"cookies": [{"name": "tok", "value": "abc", "path": "/"}]}),
        encoding="utf-8",
    )
    result = crawl_url(
        fx.origin + "/",
        depth=1,
        ignore_robots=True,
        storage_state=str(state),
    )
    names = {f.name for p in result.pages for form in p.forms for f in form.fields}
    assert "via_cookie" in names
    flagged = crawl_url(
        fx.origin + "/",
        depth=1,
        ignore_robots=True,
        cookies=["tok=abc"],
    )
    names2 = {f.name for p in flagged.pages for form in p.forms for f in form.fields}
    assert "via_cookie" in names2


def test_login_recipe_posts_and_keeps_session(fx, tmp_path):
    fx.html("/", '<a href="/secret">s</a>')

    def login(req):
        if req.method == "GET":
            body = (
                b'<form method="POST" action="/login">'
                b'<input name="user">'
                b'<input type="hidden" name="csrf" value="tok">'
                b"</form>"
            )
            return 200, {"Content-Type": "text/html; charset=utf-8"}, body
        if b"user=ok" in req.body and b"csrf=tok" in req.body:
            return 302, {"Location": "/", "Set-Cookie": "auth=yes; Path=/"}, b""
        return 401, {"Content-Type": "text/plain"}, b"no"

    def secret(req):
        html = (
            b'<form><input name="after_login"></form>'
            if "auth=yes" in req.cookies
            else b"<p>wall</p>"
        )
        return 200, {"Content-Type": "text/html; charset=utf-8"}, html

    fx.on("GET", "/login", login)
    fx.on("POST", "/login", login)
    fx.on("GET", "/secret", secret)
    recipe = tmp_path / "recipe.json"
    recipe.write_text(
        json.dumps({"url": fx.origin + "/login", "fields": {"user": "ok"}}),
        encoding="utf-8",
    )
    result = crawl_url(
        fx.origin + "/",
        depth=1,
        ignore_robots=True,
        login_recipe=str(recipe),
    )
    names = {f.name for p in result.pages for form in p.forms for f in form.fields}
    assert "after_login" in names
    paths = {urlparse(p.url).path for p in result.pages}
    assert "/secret" in paths


def _header(req, name: str) -> str:
    for k, v in req.headers.items():
        if k.lower() == name.lower():
            return v
    return ""


def test_header_and_cookie_sent_on_every_request(fx):
    seen: list[tuple[str, str]] = []

    def capture(req):
        seen.append((_header(req, "X-Lab-Auth"), req.cookies))
        html = (
            b'<form><input name="via_auth"></form>'
            if _header(req, "X-Lab-Auth") == "open" and "lab_auth=open" in req.cookies
            else b"<p>no</p>"
        )
        return 200, {"Content-Type": "text/html; charset=utf-8"}, html

    fx.html("/", '<a href="/secret">s</a>')
    fx.on("GET", "/secret", capture)
    fx.on("GET", "/robots.txt", capture)
    result = crawl_url(
        fx.origin + "/",
        depth=1,
        ignore_robots=True,
        cookies=["lab_auth=open"],
        headers=["X-Lab-Auth: open"],
    )
    assert seen
    assert all(h == "open" and "lab_auth=open" in c for h, c in seen)
    names = {f.name for p in result.pages for form in p.forms for f in form.fields}
    assert "via_auth" in names


def test_headers_do_not_bypass_local_only():
    import pytest

    with pytest.raises(ValueError, match="non-local"):
        crawl_url(
            "https://example.com/",
            depth=0,
            headers=["X-Lab-Auth: open"],
            cookies=["lab_auth=open"],
        )
