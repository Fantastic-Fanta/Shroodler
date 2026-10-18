from __future__ import annotations

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


