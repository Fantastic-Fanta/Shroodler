from __future__ import annotations

import os
from urllib.parse import urlparse

import pytest

from shroodler.crawler import crawl_url

APP1 = os.environ.get("SHROODLER_APP1", "http://127.0.0.1:8081")


def _app1_up() -> bool:
    import httpx

    try:
        return httpx.get(APP1 + "/", timeout=1.0).status_code == 200
    except httpx.HTTPError:
        return False


pytestmark = pytest.mark.skipif(not _app1_up(), reason="app1 not running")


def test_app1_graphql_unlinked_endpoint():
    result = crawl_url(APP1, depth=5)
    paths = {urlparse(p.url).path for p in result.pages}
    assert "/graphql" in paths
    assert "/graphql-hidden" not in paths
    hit = next(
        f
        for f in result.findings
        if f.id == "js-endpoint" and urlparse(f.url).path == "/graphql"
    )
    assert hit.category == "js-endpoint"
    assert hit.severity == "info"
    assert "HiddenNote" in (hit.description or "")
