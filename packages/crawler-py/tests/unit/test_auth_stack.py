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
