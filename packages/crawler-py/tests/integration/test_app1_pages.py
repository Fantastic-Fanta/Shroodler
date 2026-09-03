from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from shroodler.crawler import crawl_url
from shroodler.diffcmd import diff_documents
from shroodler.validate import validate_crawl

APP1 = os.environ.get("SHROODLER_APP1", "http://127.0.0.1:8081")
EXPECTED = (
    Path(__file__).resolve().parents[3]
    / "target-apps"
    / "app1-server-rendered"
    / "expected_findings.json"
)


def _app1_up() -> bool:
    import httpx

    try:
        r = httpx.get(APP1 + "/", timeout=1.0)
        return r.status_code == 200
    except httpx.HTTPError:
        return False


pytestmark = pytest.mark.skipif(not _app1_up(), reason="app1 not running")


def test_app1_page_discovery():
    result = crawl_url(APP1, depth=5, ignore_robots=False)
    doc = result.to_dict()
    validate_crawl(doc)
    expected = json.loads(EXPECTED.read_text(encoding="utf-8"))
    errors = diff_documents(doc, expected, pages_only=True)
    assert errors == []
    # robots.txt should hide /internal-only by default
    from urllib.parse import urlparse

    paths = {urlparse(p.url).path for p in result.pages}
    assert "/internal-only" not in paths
    assert "/sitemap-only" in paths


def test_app1_max_pages_bounds_count():
    one = crawl_url(APP1, depth=5, max_pages=1, ignore_robots=True)
    assert len(one.pages) <= 1
    assert len(one.pages) == 1
    assert one.stats is not None
    assert one.stats.stopped_reason == "max-pages"
    validate_crawl(one.to_dict())
    two = crawl_url(APP1, depth=5, max_pages=2, ignore_robots=True)
    assert len(two.pages) <= 2
    assert len(two.pages) == 2
    assert two.stats.stopped_reason == "max-pages"
