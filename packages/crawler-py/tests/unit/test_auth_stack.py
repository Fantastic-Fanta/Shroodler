from __future__ import annotations

from shroodler.crawler import crawl_url
from shroodler.extractors.auth_stack import CALLBACK_MARKER


def test_next_auth_callback_url_unvalidated(fx):
    fx.on(
        "GET",
        "/",
        lambda _req: (
            200,
            {
                "Content-Type": "text/html; charset=utf-8",
                "Set-Cookie": "__Secure-next-auth.session-token=abc; Path=/; Secure",
            },
            b"<html>app</html>",
        ),
    )
    fx.route(
        "/api/auth/providers",
        lambda _p: (200, {"Content-Type": "application/json"}, b'{"github":{"id":"github"}}'),
    )

    def signin(path: str):
        assert CALLBACK_MARKER.split("://", 1)[1] in path or "callbackUrl" in path
        return (
            200,
            {
                "Content-Type": "text/html",
                "Set-Cookie": (
                    f"__Secure-next-auth.callback-url={CALLBACK_MARKER}; Path=/; Secure"
                ),
            },
            b"<html>signin</html>",
        )

    fx.route("/api/auth/signin", signin)
    result = crawl_url(fx.origin + "/", depth=0, ignore_robots=True)
    ids = {f.id for f in result.findings}
    assert "auth-stack-next-auth" in ids
    assert "next-auth-callback-url-unvalidated" in ids
    hit = next(f for f in result.findings if f.id == "next-auth-callback-url-unvalidated")
    assert hit.severity == "medium"
    assert CALLBACK_MARKER in (hit.evidence or "")


def test_next_auth_validated_callback_does_not_fire(fx):
    fx.on(
        "GET",
        "/",
        lambda _req: (
            200,
            {
                "Content-Type": "text/html",
                "Set-Cookie": "next-auth.session-token=abc; Path=/",
            },
            b"<html>app</html>",
        ),
    )
    fx.route(
        "/api/auth/providers",
        lambda _p: (200, {"Content-Type": "application/json"}, b'{"github":{}}'),
    )
    fx.route(
        "/api/auth/signin",
        lambda _p: (
            200,
            {
                "Content-Type": "text/html",
                "Set-Cookie": "next-auth.callback-url=/dashboard; Path=/",
            },
            b"ok",
        ),
    )
    result = crawl_url(fx.origin + "/", depth=0, ignore_robots=True)
    ids = {f.id for f in result.findings}
    assert "auth-stack-next-auth" in ids
    assert "next-auth-callback-url-unvalidated" not in ids


def test_keycloak_redirect_uri_unvalidated(fx):
    from shroodler.extractors.auth_stack import OAUTH_REDIRECT_MARKER

    fx.on(
        "GET",
        "/",
        lambda _req: (
            200,
            {
                "Content-Type": "text/html",
                "Set-Cookie": "AUTH_SESSION_ID=abc; Path=/realms/app",
            },
            b'<a href="/realms/app/account">kc</a>',
        ),
    )
    fx.html("/realms/app/account", "<html>account</html>")

    def authorize(path: str):
        assert "redirect_uri=" in path
        return (
            302,
            {"Location": OAUTH_REDIRECT_MARKER + "?code=abc"},
            b"",
        )

    fx.prefix("/realms/app/protocol/openid-connect/auth", authorize)
    result = crawl_url(fx.origin + "/", depth=1, ignore_robots=True)
    ids = {f.id for f in result.findings}
    assert "auth-stack-keycloak" in ids
    assert "oauth-redirect-uri-unvalidated" in ids


def test_keycloak_error_page_echo_is_not_unvalidated(fx):
    from shroodler.extractors.auth_stack import OAUTH_REDIRECT_MARKER

    fx.on(
        "GET",
        "/",
        lambda _req: (
            200,
            {
                "Content-Type": "text/html",
                "Set-Cookie": "AUTH_SESSION_ID=abc; Path=/realms/app",
            },
            b'<a href="/realms/app/account">kc</a>',
        ),
    )
    fx.html("/realms/app/account", "<html>account</html>")

    def authorize(_path: str):
        return (
            400,
            {"Content-Type": "text/html"},
            f"<p>Invalid parameter: redirect_uri {OAUTH_REDIRECT_MARKER}</p>".encode(),
        )

    fx.prefix("/realms/app/protocol/openid-connect/auth", authorize)
    result = crawl_url(fx.origin + "/", depth=1, ignore_robots=True)
    ids = {f.id for f in result.findings}
    assert "auth-stack-keycloak" in ids
    assert "oauth-redirect-uri-unvalidated" not in ids


def test_keycloak_fingerprint_only(fx):
    fx.on(
        "GET",
        "/",
        lambda _req: (
            200,
            {
                "Content-Type": "text/html",
                "Set-Cookie": "AUTH_SESSION_ID=abc; Path=/realms/app",
            },
            b"<html>kc</html>",
        ),
    )
    result = crawl_url(fx.origin + "/", depth=0, ignore_robots=True)
    ids = {f.id for f in result.findings}
    assert "auth-stack-keycloak" in ids
    assert "next-auth-callback-url-unvalidated" not in ids


def test_no_auth_stack_on_plain_site(fx):
    fx.html("/", "<html>hello</html>")
    result = crawl_url(fx.origin + "/", depth=0, ignore_robots=True)
    ids = {f.id for f in result.findings}
    assert "auth-stack-next-auth" not in ids
    assert "auth-stack-keycloak" not in ids


def test_keycloak_login_bounce_location_is_not_unvalidated(fx):
    from shroodler.extractors.auth_stack import OAUTH_REDIRECT_MARKER

    fx.on(
        "GET",
        "/",
        lambda _req: (
            200,
            {
                "Content-Type": "text/html",
                "Set-Cookie": "AUTH_SESSION_ID=abc; Path=/realms/app",
            },
            b'<a href="/realms/app/account">kc</a>',
        ),
    )
    fx.html("/realms/app/account", "<html>account</html>")

    def authorize(_path: str):
        return (
            302,
            {"Location": f"{fx.origin}/login?next={OAUTH_REDIRECT_MARKER}"},
            b"",
        )

    fx.prefix("/realms/app/protocol/openid-connect/auth", authorize)
    result = crawl_url(fx.origin + "/", depth=1, ignore_robots=True)
    ids = {f.id for f in result.findings}
    assert "auth-stack-keycloak" in ids
    assert "oauth-redirect-uri-unvalidated" not in ids


def test_keycloak_form_post_to_marker_is_unvalidated(fx):
    from shroodler.extractors.auth_stack import OAUTH_REDIRECT_MARKER

    fx.on(
        "GET",
        "/",
        lambda _req: (
            200,
            {
                "Content-Type": "text/html",
                "Set-Cookie": "AUTH_SESSION_ID=abc; Path=/realms/app",
            },
            b'<a href="/realms/app/account">kc</a>',
        ),
    )
    fx.html("/realms/app/account", "<html>account</html>")

    def authorize(_path: str):
        html = (
            "<html><form method='post' "
            f"action='{OAUTH_REDIRECT_MARKER}'>"
            "<input name='code' value='abc'></form></html>"
        )
        return (200, {"Content-Type": "text/html"}, html.encode())

    fx.prefix("/realms/app/protocol/openid-connect/auth", authorize)
    result = crawl_url(fx.origin + "/", depth=1, ignore_robots=True)
    ids = {f.id for f in result.findings}
    assert "oauth-redirect-uri-unvalidated" in ids


def test_auth0_in_query_is_not_a_fingerprint():
    from types import SimpleNamespace

    from shroodler.extractors.auth_stack import _has_auth0

    page = SimpleNamespace(url="http://127.0.0.1/?next=https://auth0.com/login", cookies=[])
    assert not _has_auth0([], [page])


def test_keycloak_authorize_uses_origin_not_seed_path():
    from types import SimpleNamespace

    from shroodler.extractors.auth_stack import probe_redirect_uri_allowlist

    seen: list[str] = []

    class _Http:
        def request(self, method, url, anonymous=False):
            seen.append(url)
            return SimpleNamespace(status_code=400, text="", headers={}, redirect_to=None)

    page = SimpleNamespace(url="http://127.0.0.1/app/realms/app/account", cookies=[])
    probe_redirect_uri_allowlist(
        "http://127.0.0.1/app/",
        _Http(),
        [page],
        keycloak=True,
        allow_external=True,
    )
    assert seen
    assert all("/app/realms/" not in u for u in seen)
    assert any("/realms/app/protocol/openid-connect/auth" in u for u in seen)
