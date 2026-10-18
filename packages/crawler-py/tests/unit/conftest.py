"""Shared unit-test fixtures."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _default_py_crawl_engine(request, monkeypatch):
    """Keep agent unit tests on the in-process (py) crawl path.

    The production default engine is "go" (the shroodler-go subprocess), but the
    agent unit tests mock shroodler.crawler.crawl_url to exercise decision/merge
    logic deterministically, so they must not shell out to the Go binary. Force
    go_engine.available() False everywhere except test_go_engine.py, which drives
    the Go seam directly and manages availability itself.
    """
    if request.module.__name__.rsplit(".", 1)[-1] == "test_go_engine":
        return
    try:
        from shroodler import go_engine
    except Exception:
        return
    monkeypatch.setattr(go_engine, "available", lambda: False, raising=False)
