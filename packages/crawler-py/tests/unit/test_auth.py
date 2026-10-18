from __future__ import annotations

import json

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


def _header(req, name: str) -> str:
    for k, v in req.headers.items():
        if k.lower() == name.lower():
            return v
    return ""


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
        return (
            200,
            {"Content-Type": "application/json"},
            json.dumps({"access_token": "pkce-tok"}).encode(),
        )

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
    import base64
    import hashlib

    verifier, challenge = pkce_pair("abc")
    assert verifier == "abc"
    digest = hashlib.sha256(b"abc").digest()
    assert challenge == base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
