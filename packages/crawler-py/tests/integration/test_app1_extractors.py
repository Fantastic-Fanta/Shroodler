from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import urlparse

import pytest

from shroodler.crawler import crawl_url
from shroodler.diffcmd import diff_documents

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
        return httpx.get(APP1 + "/", timeout=1.0).status_code == 200
    except httpx.HTTPError:
        return False


pytestmark = pytest.mark.skipif(not _app1_up(), reason="app1 not running")


def test_app1_forms_headers_cookies():
    result = crawl_url(APP1, depth=5)
    doc = result.to_dict()
    expected = json.loads(EXPECTED.read_text(encoding="utf-8"))
    filtered = dict(expected)
    filtered["expected_findings"] = [
        f
        for f in expected["expected_findings"]
        if f["id"]
        in {
            "missing-csp",
            "insecure-cookie",
            "verbose-error",
            "server-version-leak",
        }
    ]
    errors = diff_documents(doc, filtered, pages_only=False)
    assert errors == []
    login = next(p for p in result.pages if urlparse(p.url).path == "/login")
    names = {field.name for form in login.forms for field in form.fields}
    assert {"username", "password", "csrf_token"} <= names
    dash = next(p for p in result.pages if urlparse(p.url).path == "/dashboard")
    assert any(c.name == "session_id" and c.secure is False for c in dash.cookies)
