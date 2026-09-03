from __future__ import annotations

import os
from urllib.parse import urlparse

import pytest

from shroodler.crawler import crawl_url

APP4 = os.environ.get("SHROODLER_APP4", "http://127.0.0.1:8084")


def _app4_up() -> bool:
    import httpx

    try:
        return httpx.get(APP4 + "/", timeout=1.0).status_code == 200
    except httpx.HTTPError:
        return False


pytestmark = pytest.mark.skipif(not _app4_up(), reason="app4 not running")


def test_app4_openapi_unlinked_path():
    result = crawl_url(APP4, depth=5)
    paths = {urlparse(p.url).path for p in result.pages}
    assert "/openapi.json" in paths
    assert "/internal/inventory" in paths
