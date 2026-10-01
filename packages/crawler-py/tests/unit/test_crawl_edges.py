"""Crawl JSON records the links the crawler followed."""

from __future__ import annotations

import json
from pathlib import Path

from shroodler.crawler import crawl_url
from shroodler.models import CrawlResult
from shroodler.validate import validate_crawl

_FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "scan_min.json"


def _edge_kinds(result, to_path: str) -> set[str]:
    from urllib.parse import urlparse

    kinds = set()
    for edge in result.edges:
        if urlparse(edge.to_url).path == to_path:
            kinds.add(edge.kind)
    return kinds


def test_parent_page_records_html_edge(fx):
    fx.html("/", '<a href="/child">child</a>')
    fx.html("/child", "child")
    result = crawl_url(
        fx.origin + "/", depth=1, ignore_robots=True, no_sitemap=True, max_pages=20
    )
    assert _edge_kinds(result, "/child") == {"html"}
    from urllib.parse import urlparse

    assert any(urlparse(edge.from_url).path == "/" for edge in result.edges)
    validate_crawl(result.to_dict())


def test_redirect_records_redirect_edge(fx):
    fx.html("/land", "landed")
    fx.html("/start", "go", status=302, headers={"Location": "/land"})
    result = crawl_url(
        fx.origin + "/start", depth=2, ignore_robots=True, no_sitemap=True, max_pages=20
    )
    assert _edge_kinds(result, "/land") == {"redirect"}
    validate_crawl(result.to_dict())


def test_form_action_records_form_edge(fx):
    fx.html("/", '<form action="/save"><input name="q"></form>')
    fx.html("/save", "saved")
    result = crawl_url(
        fx.origin + "/", depth=1, ignore_robots=True, no_sitemap=True, max_pages=20
    )
    assert _edge_kinds(result, "/save") == {"form"}
    validate_crawl(result.to_dict())


def test_crawl_json_without_edges_still_loads():
    doc = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    assert "edges" not in doc
    loaded = CrawlResult.model_validate(doc)
    assert loaded.edges == []
    validate_crawl(doc)
