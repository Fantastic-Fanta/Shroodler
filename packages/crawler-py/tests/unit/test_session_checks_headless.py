from __future__ import annotations

import json

from shroodler.crawler import crawl_url


def test_session_checks_are_skipped_with_a_notice_in_headless_mode(fx, tmp_path):
    fx.html(
        "/",
        '<a href="/secret">s</a>',
    )
    fx.html(
        "/login",
        '<form method="POST" action="/login">'
        '<input name="user"><button type="submit">go</button></form>',
    )

    def login(req):
        if req.method == "GET":
            return (
                200,
                {"Content-Type": "text/html; charset=utf-8"},
                b'<form method="POST" action="/login">'
                b'<input name="user"><button type="submit">go</button></form>',
            )
        return 302, {"Location": "/", "Set-Cookie": "sessionid=post-auth; Path=/"}, b""

    fx.on("GET", "/login", login)
    fx.on("POST", "/login", login)
    fx.on("GET", "/secret", lambda req: (200, {}, b"<p>secret</p>"))

    recipe = tmp_path / "recipe.json"
    recipe.write_text(json.dumps({"url": fx.origin + "/login", "fields": {"user": "ok"}}), encoding="utf-8")

    result = crawl_url(
        fx.origin + "/",
        depth=1,
        ignore_robots=True,
        mode="headless",
        login_recipe=str(recipe),
    )
    ids = {f.id for f in result.findings}
    assert "session-checks-skipped-headless" in ids
    assert "session-fixation" not in ids
    hit = next(f for f in result.findings if f.id == "session-checks-skipped-headless")
    assert hit.category == "scan-note"
