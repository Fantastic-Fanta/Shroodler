from __future__ import annotations

import os
from urllib.parse import urlparse

import pytest

from shroodler.crawler import crawl_url

APP2 = os.environ.get("SHROODLER_APP2", "http://127.0.0.1:8082")


def _app2_up() -> bool:
    import httpx

    try:
        return httpx.get(APP2 + "/", timeout=1.0).status_code == 200
    except httpx.HTTPError:
        return False


pytestmark = pytest.mark.skipif(not _app2_up(), reason="app2 not running")


def test_static_underreports_headless_finds_spa_form():
    static = crawl_url(APP2, mode="static", depth=2)
    static_forms = [f for p in static.pages for f in p.forms]
    static_paths = {urlparse(p.url).path for p in static.pages}

    headless = crawl_url(APP2, mode="headless", depth=2)
    headless_forms = [f for p in headless.pages for f in p.forms]
    headless_paths = {urlparse(p.url).path for p in headless.pages}

    assert not any(field.name == "invitee" for form in static_forms for field in form.fields)
    assert any(field.name == "invitee" for form in headless_forms for field in form.fields)
    assert "/account" in headless_paths or any(
        field.name == "email" for form in headless_forms for field in form.fields
    )
    assert "/billing" in headless_paths
    assert any(field.name == "plan" for form in headless_forms for field in form.fields)
    assert not any(field.name == "plan" for form in static_forms for field in form.fields)
    assert len(headless_forms) > len(static_forms)
    assert static_paths  # static still sees the shell
