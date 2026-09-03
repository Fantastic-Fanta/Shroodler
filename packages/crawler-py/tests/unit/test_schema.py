from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

from shroodler.validate import validate_crawl

_FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "scan_min.json"


def _base() -> dict:
    return json.loads(_FIXTURE.read_text(encoding="utf-8"))


def test_legacy_scan_without_stats_validates():
    doc = _base()
    assert "stats" not in doc
    validate_crawl(doc)


def test_scan_with_stats_validates():
    doc = _base()
    doc["stats"] = {"pages_crawled": 1, "requests": 3, "elapsed_ms": 12}
    validate_crawl(doc)


def test_required_fields_unchanged():
    doc = _base()
    for key in (
        "target",
        "scan_started_at",
        "scan_finished_at",
        "crawler",
        "pages",
        "findings",
        "js_endpoints",
    ):
        missing = deepcopy(doc)
        missing.pop(key)
        try:
            validate_crawl(missing)
        except Exception:
            continue
        raise AssertionError(f"{key} should remain required")
