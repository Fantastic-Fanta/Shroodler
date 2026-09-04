from __future__ import annotations

from shroodler.crawler import crawl_url


def test_check_rate_limit_off_by_default(fx):
    fx.html(
        "/",
        '<form method="post" action="/login">'
        '<input name="username"><input name="password" type="password">'
        "</form>",
    )
    fx.on("POST", "/login", lambda inc: (200, {}, b"invalid credentials"))
    result = crawl_url(fx.origin + "/", depth=1, ignore_robots=True)
    ids = {f.id for f in result.findings}
    assert "missing-rate-limit" not in ids
    assert not any(m == "POST" and p == "/login" for m, p in fx.calls)


def test_check_rate_limit_flags_unthrottled_login(fx):
    fx.html(
        "/",
        '<form method="post" action="/login">'
        '<input name="username"><input name="password" type="password">'
        "</form>",
    )
    fx.on("POST", "/login", lambda inc: (200, {}, b"invalid credentials"))
    result = crawl_url(fx.origin + "/", depth=1, ignore_robots=True, check_rate_limit=True)
    hits = [f for f in result.findings if f.id == "missing-rate-limit"]
    assert len(hits) == 1
    assert hits[0].category == "auth"
    login_posts = [1 for m, p in fx.calls if m == "POST" and p == "/login"]
    assert len(login_posts) >= 5


def test_check_rate_limit_silent_when_throttled(fx):
    fx.html(
        "/",
        '<form method="post" action="/login">'
        '<input name="username"><input name="password" type="password">'
        "</form>",
    )
    attempts = {"n": 0}

    def handle(inc):
        attempts["n"] += 1
        if attempts["n"] >= 3:
            return 429, {}, b"too many requests"
        return 200, {}, b"invalid credentials"

    fx.on("POST", "/login", handle)
    result = crawl_url(fx.origin + "/", depth=1, ignore_robots=True, check_rate_limit=True)
    ids = {f.id for f in result.findings}
    assert "missing-rate-limit" not in ids
