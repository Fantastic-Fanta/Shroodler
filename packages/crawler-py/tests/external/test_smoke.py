from __future__ import annotations

import os

import pytest

from shroodler.crawler import crawl_url
from shroodler.validate import validate_crawl

pytestmark = pytest.mark.skipif(
    os.environ.get("SHROODLER_ALLOW_EXTERNAL") != "1",
    reason="external smoke is opt-in; never part of make verify",
)


def test_httpbin_allow_external_smoke():
    result = crawl_url(
        "https://httpbin.org/get",
        depth=0,
        allow_external=True,
        ignore_robots=False,
        max_pages=3,
    )
    doc = result.to_dict()
    validate_crawl(doc)
    assert doc["pages"]
