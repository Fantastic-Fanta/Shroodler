from __future__ import annotations

from shroodler.crawler import crawl_url


def test_set_cookie_roundtrip_via_http(fx):
    fx.route(
        "/",
        lambda _r: (
            200,
            {
                "Content-Type": "text/html; charset=utf-8",
                "Set-Cookie": "session_id=abc; HttpOnly; SameSite=Lax",
            },
            b"<html></html>",
        ),
    )
    result = crawl_url(fx.origin + "/", depth=0)
    assert result.pages[0].cookies
    c = result.pages[0].cookies[0]
    assert c.name == "session_id"
    assert c.secure is False
    assert c.http_only is True
    assert c.same_site == "Lax"
    assert any(f.id == "insecure-cookie" for f in result.findings)
