from __future__ import annotations

from shroodler.crawler import crawl_url
from shroodler.sitemap import parse_robots_sitemaps, parse_sitemap_xml


def _paths(result) -> set[str]:
    from urllib.parse import urlparse

    return {urlparse(p.url).path for p in result.pages}


def test_parse_robots_sitemap_directives():
    body = (
        "User-agent: *\n"
        "Disallow: /hidden\n"
        "Sitemap: http://127.0.0.1:8081/sitemap.xml\n"
        "sitemap: /alt.xml\n"
        "# Sitemap: http://evil.example/ignore.xml\n"
        "Sitemap:\n"
        "Sitemap: http://127.0.0.1:8081/other.xml # comment\n"
    )
    got = parse_robots_sitemaps(body)
    assert got == [
        "http://127.0.0.1:8081/sitemap.xml",
        "/alt.xml",
        "http://127.0.0.1:8081/other.xml",
    ]
    assert parse_robots_sitemaps("") == []
    assert parse_robots_sitemaps("User-agent: *\nDisallow: /\n") == []


def test_parse_sitemap_xml_locs_and_index():
    urlset = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://127.0.0.1/a</loc></url>
  <url><loc>http://127.0.0.1/b</loc></url>
</urlset>
"""
    urls, nested = parse_sitemap_xml(urlset)
    assert urls == ["http://127.0.0.1/a", "http://127.0.0.1/b"]
    assert nested == []

    index = """<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap><loc>http://127.0.0.1/sitemap-pages.xml</loc></sitemap>
</sitemapindex>
"""
    urls, nested = parse_sitemap_xml(index)
    assert urls == []
    assert nested == ["http://127.0.0.1/sitemap-pages.xml"]


def test_malformed_sitemap_xml_does_not_crash():
    assert parse_sitemap_xml("") == ([], [])
    assert parse_sitemap_xml("not xml at all <<>>") == ([], [])
    assert parse_sitemap_xml("<urlset><url><loc>http://127.0.0.1/x</loc>") == ([], [])


def test_sitemap_only_page_is_discovered(fx):
    fx.html("/", "<p>home</p>")
    fx.html("/sitemap-only", "<h1>unlinked</h1>")
    fx.route(
        "/sitemap.xml",
        lambda _r: (
            200,
            {"Content-Type": "application/xml"},
            (
                '<?xml version="1.0"?>\n'
                "<urlset xmlns='http://www.sitemaps.org/schemas/sitemap/0.9'>"
                f"<url><loc>{fx.origin}/sitemap-only</loc></url>"
                "</urlset>"
            ).encode(),
        ),
    )
    result = crawl_url(fx.origin + "/", depth=0)
    assert "/sitemap-only" in _paths(result)


def test_robots_sitemap_directive_seeds(fx):
    fx.html("/", "<p>home</p>")
    fx.html("/from-robots", "<h1>via robots Sitemap</h1>")
    fx.route(
        "/robots.txt",
        lambda _r: (
            200,
            {"Content-Type": "text/plain"},
            f"User-agent: *\nSitemap: {fx.origin}/alt-sitemap.xml\n".encode(),
        ),
    )
    fx.route(
        "/alt-sitemap.xml",
        lambda _r: (
            200,
            {"Content-Type": "application/xml"},
            (
                "<urlset><url><loc>"
                f"{fx.origin}/from-robots"
                "</loc></url></urlset>"
            ).encode(),
        ),
    )
    result = crawl_url(fx.origin + "/", depth=0)
    assert "/from-robots" in _paths(result)


def test_nested_sitemap_index(fx):
    fx.html("/", "<p>home</p>")
    fx.html("/nested-only", "<h1>nested</h1>")
    fx.route(
        "/sitemap.xml",
        lambda _r: (
            200,
            {"Content-Type": "application/xml"},
            (
                "<sitemapindex><sitemap><loc>"
                f"{fx.origin}/nested.xml"
                "</loc></sitemap></sitemapindex>"
            ).encode(),
        ),
    )
    fx.route(
        "/nested.xml",
        lambda _r: (
            200,
            {"Content-Type": "application/xml"},
            (
                "<urlset><url><loc>"
                f"{fx.origin}/nested-only"
                "</loc></url></urlset>"
            ).encode(),
        ),
    )
    result = crawl_url(fx.origin + "/", depth=0)
    assert "/nested-only" in _paths(result)


def test_off_host_sitemap_locs_are_ignored(fx):
    fx.html("/", "<p>home</p>")
    fx.html("/local", "<h1>local</h1>")
    fx.route(
        "/sitemap.xml",
        lambda _r: (
            200,
            {"Content-Type": "application/xml"},
            (
                "<urlset>"
                "<url><loc>http://example.com/public</loc></url>"
                f"<url><loc>{fx.origin}/local</loc></url>"
                "</urlset>"
            ).encode(),
        ),
    )
    result = crawl_url(fx.origin + "/", depth=0)
    paths = _paths(result)
    assert "/local" in paths
    assert all("example.com" not in p.url for p in result.pages)


def test_no_sitemap_flag_skips_discovery(fx):
    fx.html("/", "<p>home</p>")
    fx.html("/sitemap-only", "<h1>unlinked</h1>")
    fx.route(
        "/sitemap.xml",
        lambda _r: (
            200,
            {"Content-Type": "application/xml"},
            (
                "<urlset><url><loc>"
                f"{fx.origin}/sitemap-only"
                "</loc></url></urlset>"
            ).encode(),
        ),
    )
    result = crawl_url(fx.origin + "/", depth=0, no_sitemap=True)
    assert "/sitemap-only" not in _paths(result)
