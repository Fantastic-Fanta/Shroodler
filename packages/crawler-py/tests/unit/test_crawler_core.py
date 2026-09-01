from __future__ import annotations

from shroodler.crawler import crawl_url
from shroodler.urls import canonical_key, same_origin
from shroodler.validate import validate_crawl


def _paths(result) -> set[str]:
    from urllib.parse import urlparse

    return {urlparse(p.url).path for p in result.pages}


def test_depth_zero_stays_on_seed(fx):
    fx.html("/", '<a href="/only">x</a>')
    fx.html("/only", "only")
    result = crawl_url(fx.origin + "/", depth=0)
    assert _paths(result) == {"/"}


def test_depth_one_follows_once(fx):
    fx.html("/", '<a href="/a">a</a>')
    fx.html("/a", '<a href="/b">b</a>')
    fx.html("/b", "b")
    result = crawl_url(fx.origin + "/", depth=1)
    assert _paths(result) == {"/", "/a"}


def test_depth_two(fx):
    fx.html("/", '<a href="/a">a</a>')
    fx.html("/a", '<a href="/b">b</a>')
    fx.html("/b", '<a href="/c">c</a>')
    fx.html("/c", "c")
    result = crawl_url(fx.origin + "/", depth=2)
    assert _paths(result) == {"/", "/a", "/b"}


def test_depth_five_and_ten(fx):
    fx.html("/", '<a href="/p/1">1</a>')

    def chain(req: str):
        from urllib.parse import urlparse

        n = int(urlparse(req).path.rsplit("/", 1)[-1])
        body = f'<a href="/p/{n + 1}">{n + 1}</a>'
        return 200, {"Content-Type": "text/html; charset=utf-8"}, body.encode()

    fx.prefix("/p/", chain)
    r5 = crawl_url(fx.origin + "/", depth=5)
    assert "/p/5" in _paths(r5)
    assert "/p/6" not in _paths(r5)
    r10 = crawl_url(fx.origin + "/", depth=10)
    assert "/p/10" in _paths(r10)
    assert "/p/11" not in _paths(r10)


def test_unbounded_depth_still_bounded_by_max_pages(fx):
    fx.html("/", '<a href="/q/1">1</a>')

    def unique(req: str):
        from urllib.parse import urlparse

        rest = urlparse(req).path.strip("/").split("/")[-1]
        n = int(rest)
        body = f'<a href="/q/{n + 1}">n</a>'
        return 200, {"Content-Type": "text/html; charset=utf-8"}, body.encode()

    fx.prefix("/q/", unique)
    result = crawl_url(fx.origin + "/", depth=None, max_pages=12)
    assert len(result.pages) <= 12
    assert len(result.pages) == 12


def test_same_origin_kept_cross_origin_dropped(fx):
    fx.html(
        "/",
        f'<a href="/local">L</a>'
        f'<a href="http://example.com/x">x</a>'
        f'<a href="//example.net/y">y</a>'
        f'<a href="{fx.origin}/local2">l2</a>',
    )
    fx.html("/local", "ok")
    fx.html("/local2", "ok")
    result = crawl_url(fx.origin + "/", depth=2)
    paths = _paths(result)
    assert "/local" in paths
    assert "/local2" in paths
    for page in result.pages:
        assert same_origin(page.url, fx.origin + "/")


def test_path_and_protocol_relative_links(fx):
    host = fx.origin.split("://", 1)[1]
    fx.html(
        "/dir/page",
        f'<a href="sibling">s</a>'
        f'<a href="/abs">a</a>'
        f'<a href="//{host}/proto">p</a>',
    )
    fx.html("/dir/sibling", "s")
    fx.html("/abs", "a")
    fx.html("/proto", "p")
    result = crawl_url(fx.origin + "/dir/page", depth=1)
    assert {"/dir/page", "/dir/sibling", "/abs", "/proto"} <= _paths(result)


def test_link_forms(fx):
    fx.html(
        "/",
        """
        <a href="/from-a">a</a>
        <form action="/from-form"></form>
        <link rel="stylesheet" href="/from-link.css">
        <script src="/from-script.js"></script>
        <style>body { background: url(/from-css.png); }</style>
        <meta http-equiv="refresh" content="0;url=/from-meta">
        """,
    )
    for path in (
        "/from-a",
        "/from-form",
        "/from-link.css",
        "/from-script.js",
        "/from-css.png",
        "/from-meta",
    ):
        fx.html(path, "x")
    result = crawl_url(fx.origin + "/", depth=1)
    assert {
        "/from-a",
        "/from-form",
        "/from-link.css",
        "/from-script.js",
        "/from-css.png",
        "/from-meta",
    } <= _paths(result)


def test_single_redirect_and_chain(fx):
    def redir(to: str, status: int = 302):
        def handle(_req: str):
            return status, {"Location": to, "Content-Type": "text/html"}, b""

        return handle

    fx.route("/go", redir("/land"))
    fx.html("/land", "landed")
    fx.route("/r1", redir("/r2", 301))
    fx.route("/r2", redir("/r3"))
    fx.route("/r3", redir("/r4"))
    fx.route("/r4", redir("/r5"))
    fx.route("/r5", redir("/r6"))
    fx.html("/r6", "end")
    one = crawl_url(fx.origin + "/go", depth=2)
    assert "/go" in _paths(one) and "/land" in _paths(one)
    chain = crawl_url(fx.origin + "/r1", depth=10)
    assert {"/r1", "/r2", "/r3", "/r4", "/r5", "/r6"} <= _paths(chain)


def test_redirect_loop_stops(fx):
    fx.route("/loop-a", lambda _r: (302, {"Location": "/loop-b"}, b""))
    fx.route("/loop-b", lambda _r: (302, {"Location": "/loop-a"}, b""))
    result = crawl_url(fx.origin + "/loop-a", depth=10, max_pages=20)
    assert len(result.pages) <= 4


def test_malformed_html_and_non_utf8(fx):
    fx.html("/", "<div><p>unclosed<span>nest</div><a href='/ok'>ok")
    fx.html("/ok", "ok")
    fx.route(
        "/latin",
        lambda _r: (
            200,
            {"Content-Type": "text/html; charset=latin-1"},
            "café".encode("latin-1") + b'<a href="/ok2">x</a>',
        ),
    )
    fx.html("/ok2", "ok2")
    malformed = crawl_url(fx.origin + "/", depth=1)
    assert "/ok" in _paths(malformed)
    latin = crawl_url(fx.origin + "/latin", depth=1)
    assert any(p.status_code == 200 for p in latin.pages)


def test_duplicate_detection(fx):
    fx.html(
        "/",
        """
        <a href="/dup">a</a>
        <a href="/dup/">b</a>
        <a href="/dup?b=2&a=1">c</a>
        <a href="/dup?a=1&b=2">d</a>
        <a href="/dup#frag">e</a>
        """,
    )
    fx.html("/dup", "dup")
    result = crawl_url(fx.origin + "/", depth=1)
    keys = [canonical_key(p.url) for p in result.pages if "/dup" in p.url]
    assert len(keys) == len(set(keys))
    assert len([p for p in result.pages if canonical_key(p.url).rstrip("/").endswith("/dup")]) <= 2


def test_rate_limit_429(fx):
    state = {"n": 0}

    def limited(_req: str):
        state["n"] += 1
        if state["n"] < 3:
            return 429, {"Retry-After": "0", "Content-Type": "text/plain"}, b"slow"
        return 200, {"Content-Type": "text/html; charset=utf-8"}, b"ok"

    fx.route("/limited", limited)
    result = crawl_url(fx.origin + "/limited", depth=0)
    assert result.pages[0].status_code == 200


def test_robots_respected_and_ignorable(fx):
    fx.route(
        "/robots.txt",
        lambda _r: (200, {"Content-Type": "text/plain"}, b"User-agent: *\nDisallow: /hidden\n"),
    )
    fx.html("/", '<a href="/hidden">h</a><a href="/visible">v</a>')
    fx.html("/hidden", "no")
    fx.html("/visible", "yes")
    respected = crawl_url(fx.origin + "/", depth=1, ignore_robots=False)
    assert "/hidden" not in _paths(respected)
    assert "/visible" in _paths(respected)
    ignored = crawl_url(fx.origin + "/", depth=1, ignore_robots=True)
    assert "/hidden" in _paths(ignored)


def test_pagination_trap(fx):
    fx.html("/", '<a href="/page/1">n</a>')

    def pages(req: str):
        from urllib.parse import urlparse

        n = int(urlparse(req).path.rsplit("/", 1)[-1])
        body = f'<html><a href="/page/{n + 1}">next</a></html>'
        return 200, {"Content-Type": "text/html; charset=utf-8"}, body.encode()

    fx.prefix("/page/", pages)
    result = crawl_url(fx.origin + "/", depth=None, max_pages=100)
    page_paths = [p for p in _paths(result) if p.startswith("/page/")]
    assert len(page_paths) <= 10


def test_honeypot_links_skipped(fx):
    fx.html(
        "/",
        """
        <a href="/real">real</a>
        <a href="/hidden-attr" hidden>x</a>
        <a href="/display-none" style="display:none">x</a>
        <div style="visibility:hidden"><a href="/vis-hidden">x</a></div>
        <a class="honeypot" href="/class-hp">x</a>
        """,
    )
    for p in ("/real", "/hidden-attr", "/display-none", "/vis-hidden", "/class-hp"):
        fx.html(p, "x")
    result = crawl_url(fx.origin + "/", depth=1)
    paths = _paths(result)
    assert "/real" in paths
    assert "/hidden-attr" not in paths
    assert "/display-none" not in paths
    assert "/vis-hidden" not in paths
    assert "/class-hp" not in paths


def test_output_validates_against_schema(fx):
    fx.html("/", "<p>hi</p>")
    result = crawl_url(fx.origin + "/", depth=0)
    validate_crawl(result.model_dump(mode="json"))


def test_refuses_external_without_flag():
    try:
        crawl_url("http://example.com/", depth=0)
        raise AssertionError("should have refused")
    except ValueError as exc:
        assert "non-local" in str(exc)
