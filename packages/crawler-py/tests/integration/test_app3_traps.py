from __future__ import annotations

import json
import os
import time
from pathlib import Path
from urllib.parse import urlparse

import pytest

from shroodler.crawler import crawl_url
from shroodler.diffcmd import diff_documents

APP3 = os.environ.get("SHROODLER_APP3", "http://127.0.0.1:8083")
EXPECTED = (
    Path(__file__).resolve().parents[3]
    / "target-apps"
    / "app3-crawler-traps"
    / "expected_findings.json"
)


def _up() -> bool:
    import httpx

    try:
        return httpx.get(APP3 + "/", timeout=1.0).status_code == 200
    except httpx.HTTPError:
        return False


pytestmark = pytest.mark.skipif(not _up(), reason="app3 not running")


def test_app3_completes_bounded_and_matches():
    start = time.monotonic()
    result = crawl_url(APP3, depth=None, max_pages=80)
    elapsed = time.monotonic() - start
    assert elapsed < 30
    paths = {urlparse(p.url).path for p in result.pages}
    assert "/visible" in paths
    assert not any(p.startswith("/secret-honey") for p in paths)
    assert not any(p.startswith("/offscreen") for p in paths)
    assert not any(p.startswith("/class-hp") for p in paths)
    page_ns = [p for p in paths if p.startswith("/page/")]
    assert len(page_ns) <= 12
    expected = json.loads(EXPECTED.read_text(encoding="utf-8"))
    errors = diff_documents(result.to_dict(), expected, pages_only=False)
    assert errors == []


def test_app3_max_time_completes_without_hang():
    start = time.monotonic()
    result = crawl_url(APP3, depth=None, max_pages=400, max_time=0.01)
    elapsed = time.monotonic() - start
    assert elapsed < 8
    assert result.stats is not None
    assert result.stats.stopped_reason == "max-time"
    from shroodler.validate import validate_crawl

    validate_crawl(result.to_dict())
