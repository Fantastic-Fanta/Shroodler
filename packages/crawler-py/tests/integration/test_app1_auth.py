from __future__ import annotations

import os

import pytest

from shroodler.crawler import crawl_url

APP1 = os.environ.get("SHROODLER_APP1", "http://127.0.0.1:8081")


def _app1_up() -> bool:
    import httpx

    try:
        return httpx.get(APP1 + "/", timeout=1.0, trust_env=False).status_code == 200
    except httpx.HTTPError:
        return False


pytestmark = pytest.mark.skipif(not _app1_up(), reason="app1 not running")


def test_cookie_and_header_unlock_lab_gated():
    gated = APP1.rstrip("/") + "/lab-gated"

    def field_names(result) -> set[str]:
        return {f.name for p in result.pages for form in p.forms for f in form.fields}

    anon = crawl_url(APP1, depth=0, ignore_robots=True, extra_seeds=[gated])
    via_cookie = crawl_url(
        APP1,
        depth=0,
        ignore_robots=True,
        extra_seeds=[gated],
        cookies=["lab_auth=open"],
    )
    via_header = crawl_url(
        APP1,
        depth=0,
        ignore_robots=True,
        extra_seeds=[gated],
        headers=["X-Lab-Auth: open"],
    )
    assert "lab_gated_field" not in field_names(anon)
    assert "lab_gated_field" in field_names(via_cookie)
    assert "lab_gated_field" in field_names(via_header)
