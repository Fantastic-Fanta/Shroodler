from __future__ import annotations

from urllib.parse import urlparse

from shroodler.crawler import crawl_url


def test_headless_click_finds_router_only_path(fx):
    fx.html(
        "/",
        """
        <html><body>
          <button type="button" id="go"
            onclick="history.pushState({}, '', '/hidden-route')">Open</button>
        </body></html>
        """,
    )
    fx.html(
        "/hidden-route",
        '<form action="/x" method="POST"><input name="clicked"></form>',
    )
    static = crawl_url(fx.origin + "/", mode="static", depth=1, ignore_robots=True)
    headless = crawl_url(fx.origin + "/", mode="headless", depth=1, ignore_robots=True)
    static_paths = {urlparse(p.url).path for p in static.pages}
    headless_paths = {urlparse(p.url).path for p in headless.pages}
    names = {f.name for p in headless.pages for form in p.forms for f in form.fields}
    assert "/hidden-route" not in static_paths
    assert "/hidden-route" in headless_paths
    assert "clicked" in names


def test_headless_click_skips_honeypot_and_bounds(fx):
    buttons = []
    for i in range(30):
        dest = f"/p/{i}"
        buttons.append(
            "<button type=\"button\" onclick="
            f"\"history.pushState({{}},&quot;&quot;,&quot;{dest}&quot;)\">b</button>"
        )
    honey = (
        '<button type="button" class="honeypot" '
        'onclick="history.pushState({},&quot;&quot;,&quot;/trap&quot;)">x</button>'
    )
    fx.html("/", "<html><body>" + "".join(buttons) + honey + "</body></html>")
    fx.prefix(
        "/p/",
        lambda req: (200, {"Content-Type": "text/html; charset=utf-8"}, b"<p>ok</p>"),
    )
    fx.html("/trap", "<p>trap</p>")
    result = crawl_url(
        fx.origin + "/",
        mode="headless",
        depth=1,
        ignore_robots=True,
        max_pages=20,
    )
    paths = {urlparse(p.url).path for p in result.pages}
    assert "/trap" not in paths
    assert len(result.pages) <= 20
