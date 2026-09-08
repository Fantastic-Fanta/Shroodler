from __future__ import annotations

import json
from urllib.parse import urlparse

import pytest

from shroodler.auth import (
    cookies_from_json,
    cookies_from_netscape,
    load_cookie_jar,
    load_login_recipe,
    parse_cookie_pairs,
    parse_header_lines,
    pkce_pair,
    run_hook_step,
    run_login_httpx,
    run_oauth_pkce_step,
)
from shroodler.crawler import crawl_url


@pytest.fixture(autouse=True)
def _no_reauth_sleep(monkeypatch):
    monkeypatch.setattr("shroodler.crawler.sleep", lambda *_a, **_k: None)


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
    assert recipe.local_storage == {}
    assert recipe.auth_marker is None


def test_load_login_recipe_local_storage_and_auth_marker(tmp_path):
    p = tmp_path / "login.json"
    p.write_text(
        json.dumps({
            "url": "https://example.com/api/login",
            "content_type": "json",
            "fields": {},
            "local_storage": {"loginData": "eyJhbGci..."},
            "auth_marker": "myusername",
            "protected_url": "https://example.com/dashboard",
        }),
        encoding="utf-8",
    )
    recipe = load_login_recipe(str(p))
    assert recipe.local_storage == {"loginData": "eyJhbGci..."}
    assert recipe.auth_marker == "myusername"
    assert recipe.protected_url == "https://example.com/dashboard"


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


def _login_handlers(fx, logins: dict):
    def login(req):
        if req.method == "GET":
            body = (
                b'<form method="POST" action="/login">'
                b'<input name="user">'
                b'<input type="hidden" name="csrf" value="tok">'
                b"</form>"
            )
            return 200, {"Content-Type": "text/html; charset=utf-8"}, body
        logins["n"] += 1
        return 302, {"Location": "/", "Set-Cookie": "auth=yes; Path=/"}, b""

    fx.on("GET", "/login", login)
    fx.on("POST", "/login", login)
    return fx.origin + "/login"


def test_reauth_on_401_retries_once(fx, tmp_path):
    from urllib.parse import urlparse

    logins = {"n": 0}
    login_url = _login_handlers(fx, logins)
    fx.html("/", '<a href="/secret">s</a>')

    def secret(req):
        if logins["n"] < 2:
            return 401, {"Content-Type": "text/plain"}, b"expired"
        html = (
            b'<form><input name="after_reauth"></form>'
            if "auth=yes" in req.cookies
            else b"<p>wall</p>"
        )
        return 200, {"Content-Type": "text/html; charset=utf-8"}, html

    fx.on("GET", "/secret", secret)
    recipe = tmp_path / "recipe.json"
    recipe.write_text(json.dumps({"url": login_url, "fields": {"user": "ok"}}), encoding="utf-8")
    result = crawl_url(
        fx.origin + "/",
        depth=1,
        ignore_robots=True,
        login_recipe=str(recipe),
    )
    assert logins["n"] == 2
    names = {f.name for p in result.pages for form in p.forms for f in form.fields}
    assert "after_reauth" in names
    assert "/secret" in {urlparse(p.url).path for p in result.pages}
    assert any(f.id == "session-reauthenticated" for f in result.findings)


def test_reauth_on_login_redirect(fx, tmp_path):
    logins = {"n": 0}
    login_url = _login_handlers(fx, logins)
    fx.html("/", '<a href="/secret">s</a>')

    def secret(req):
        if logins["n"] < 2:
            return 302, {"Location": "/login"}, b""
        return 200, {"Content-Type": "text/html; charset=utf-8"}, b"<p>ok</p>"

    fx.on("GET", "/secret", secret)
    recipe = tmp_path / "recipe.json"
    recipe.write_text(json.dumps({"url": login_url, "fields": {"user": "ok"}}), encoding="utf-8")
    result = crawl_url(
        fx.origin + "/",
        depth=1,
        ignore_robots=True,
        login_recipe=str(recipe),
    )
    assert logins["n"] == 2
    assert any(f.id == "session-reauthenticated" for f in result.findings)


def test_reauth_capped_at_retries(fx, tmp_path):
    logins = {"n": 0}
    login_url = _login_handlers(fx, logins)
    fx.html("/", '<a href="/a">a</a><a href="/b">b</a>')

    def always_401(_req):
        return 401, {"Content-Type": "text/plain"}, b"no"

    fx.on("GET", "/a", always_401)
    fx.on("GET", "/b", always_401)
    recipe = tmp_path / "recipe.json"
    recipe.write_text(json.dumps({"url": login_url, "fields": {"user": "ok"}}), encoding="utf-8")
    result = crawl_url(
        fx.origin + "/",
        depth=1,
        ignore_robots=True,
        login_recipe=str(recipe),
        reauth_max_retries=2,
    )
    # prime + 2 mid-crawl re-auths on /a, then session-died (never reaches /b)
    assert logins["n"] == 3
    died = [f for f in result.findings if f.id == "session-died"]
    assert len(died) == 1
    assert died[0].severity == "high"
    assert died[0].category == "scan-note"
    assert str(logins["n"])  # smoke
    paths = {urlparse(p.url).path for p in result.pages}
    assert "/b" not in paths


def test_reauth_retry_countdown_backoff(fx, tmp_path, monkeypatch):
    delays: list[float] = []
    monkeypatch.setattr("shroodler.crawler.sleep", lambda d: delays.append(d))
    logins = {"n": 0}
    login_url = _login_handlers(fx, logins)
    fx.html("/", '<a href="/secret">s</a>')
    fx.on("GET", "/secret", lambda _req: (401, {"Content-Type": "text/plain"}, b"no"))
    recipe = tmp_path / "recipe.json"
    recipe.write_text(json.dumps({"url": login_url, "fields": {"user": "ok"}}), encoding="utf-8")
    result = crawl_url(
        fx.origin + "/",
        depth=1,
        ignore_robots=True,
        login_recipe=str(recipe),
        reauth_max_retries=3,
    )
    assert delays == [1, 2, 4]
    died = next(f for f in result.findings if f.id == "session-died")
    assert died.severity == "high"
    assert "requests=" in (died.description or "")
    assert "last good URL" in (died.description or "")
    assert died.url  # last good URL (seed /)
    assert "requests=" in (died.evidence or "")


def test_session_died_includes_last_good_url_and_request_count(fx, tmp_path):
    logins = {"n": 0}
    login_url = _login_handlers(fx, logins)
    fx.html("/", '<a href="/ok">ok</a><a href="/dead">dead</a>')
    fx.on("GET", "/ok", lambda _req: (200, {"Content-Type": "text/html; charset=utf-8"}, b"<p>ok</p>"))
    fx.on("GET", "/dead", lambda _req: (401, {"Content-Type": "text/plain"}, b"no"))
    recipe = tmp_path / "recipe.json"
    recipe.write_text(json.dumps({"url": login_url, "fields": {"user": "ok"}}), encoding="utf-8")
    result = crawl_url(
        fx.origin + "/",
        depth=1,
        ignore_robots=True,
        login_recipe=str(recipe),
        reauth_max_retries=1,
    )
    died = next(f for f in result.findings if f.id == "session-died")
    assert "/ok" in died.url or died.url.rstrip("/").endswith("")
    assert "requests=" in died.description
    assert result.stats is None or result.stats.requests >= 1


def test_no_reauth_without_login_recipe(fx):
    fx.html("/", '<a href="/secret">s</a>')
    fx.on("GET", "/secret", lambda _req: (401, {"Content-Type": "text/plain"}, b"no"))
    result = crawl_url(fx.origin + "/", depth=1, ignore_robots=True)
    assert not any(f.id == "session-reauthenticated" for f in result.findings)
    assert not any(f.id == "session-died" for f in result.findings)


def test_load_login_recipe_oauth_pkce_and_hook_steps(tmp_path):
    p = tmp_path / "login.json"
    p.write_text(
        json.dumps(
            {
                "url": "https://idp.example/oauth/token",
                "steps": [
                    {"type": "hook", "command": "echo tok", "header_name": "X-Castle"},
                    {
                        "type": "oauth_pkce",
                        "token_url": "https://idp.example/oauth/token",
                        "client_id": "app",
                        "scope": "openid",
                        "client_secret": "s",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    recipe = load_login_recipe(str(p))
    types = [s.type for s in recipe.steps]
    assert types == ["hook", "oauth_pkce"]
    assert recipe.steps[1].client_id == "app"
    assert recipe.steps[1].scope == "openid"


def test_oauth_pkce_step_client_credentials(fx):
    import httpx

    seen: dict[str, str] = {}

    def token(req):
        seen["body"] = req.body.decode("utf-8")
        body = json.dumps({"access_token": "tok-abc", "token_type": "Bearer"})
        return 200, {"Content-Type": "application/json"}, body.encode()

    fx.on("POST", "/oauth/token", token)
    client = httpx.Client(follow_redirects=True)
    from shroodler.auth import RecipeStep

    token_str = run_oauth_pkce_step(
        client,
        RecipeStep(
            type="oauth_pkce",
            token_url=fx.origin + "/oauth/token",
            client_id="cid",
            scope="api",
            client_secret="sekrit",
        ),
    )
    assert token_str == "tok-abc"
    assert client.headers["Authorization"] == "Bearer tok-abc"
    assert "grant_type=client_credentials" in seen["body"]
    assert "client_id=cid" in seen["body"]
    client.close()


def test_oauth_pkce_step_authorization_code(fx):
    import httpx

    seen: dict[str, str] = {}

    def token(req):
        seen["body"] = req.body.decode("utf-8")
        return 200, {"Content-Type": "application/json"}, json.dumps({"access_token": "pkce-tok"}).encode()

    fx.on("POST", "/oauth/token", token)
    client = httpx.Client(follow_redirects=True)
    from shroodler.auth import RecipeStep

    run_oauth_pkce_step(
        client,
        RecipeStep(
            type="oauth_pkce",
            token_url=fx.origin + "/oauth/token",
            client_id="cid",
            code="authcode",
            code_verifier="verifier-value-here",
            redirect_uri="http://127.0.0.1/cb",
        ),
    )
    assert "grant_type=authorization_code" in seen["body"]
    assert "code_verifier=verifier-value-here" in seen["body"]
    assert client.headers["Authorization"] == "Bearer pkce-tok"
    client.close()


def test_hook_step_execution(tmp_path):
    import httpx

    marker = tmp_path / "castle.txt"
    from shroodler.auth import RecipeStep

    client = httpx.Client()
    run_hook_step(
        client,
        RecipeStep(
            type="hook",
            command=["python3", "-c", f"open({str(marker)!r}, 'w').write('castle-tok')"],
            header_from_file=str(marker),
            header_name="X-Castle-Request-Token",
        ),
    )
    assert marker.read_text() == "castle-tok"
    assert client.headers["X-Castle-Request-Token"] == "castle-tok"
    client.close()


def test_login_recipe_runs_hook_then_oauth(fx, tmp_path):
    import httpx

    marker = tmp_path / "hook.ran"
    fx.on(
        "POST",
        "/oauth/token",
        lambda req: (
            200,
            {"Content-Type": "application/json"},
            json.dumps({"access_token": "from-recipe"}).encode(),
        ),
    )
    recipe = tmp_path / "recipe.json"
    recipe.write_text(
        json.dumps(
            {
                "url": fx.origin + "/oauth/token",
                "steps": [
                    {
                        "type": "hook",
                        "command": ["python3", "-c", f"open({str(marker)!r}, 'w').write('ok')"],
                    },
                    {
                        "type": "oauth_pkce",
                        "token_url": fx.origin + "/oauth/token",
                        "client_id": "cid",
                        "client_secret": "s",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    loaded = load_login_recipe(str(recipe))
    client = httpx.Client(follow_redirects=True)
    run_login_httpx(client, loaded)
    assert marker.read_text() == "ok"
    assert client.headers["Authorization"] == "Bearer from-recipe"
    client.close()


def test_pkce_pair_s256():
    import hashlib
    import base64

    verifier, challenge = pkce_pair("abc")
    assert verifier == "abc"
    digest = hashlib.sha256(b"abc").digest()
    assert challenge == base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
