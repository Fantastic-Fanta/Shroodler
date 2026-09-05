from __future__ import annotations

from pathlib import Path

from shroodler.history import (
    list_scans,
    load_scan,
    record_scan,
    render_trend_text,
    trend_diff,
)


def _doc(target: str, findings: list[dict], finished_at: str = "2026-01-01T00:00:00Z") -> dict:
    return {"target": target, "scan_finished_at": finished_at, "findings": findings}


def test_record_and_list_scan(tmp_path):
    hdir = tmp_path / "hist"
    doc = _doc("http://127.0.0.1:8081/", [{"id": "a", "url": "http://127.0.0.1:8081/"}])
    path = record_scan(doc, hdir, label="nightly")
    assert path.is_file()
    entries = list_scans(hdir)
    assert len(entries) == 1
    assert entries[0]["target"] == "http://127.0.0.1:8081/"
    assert entries[0]["findings"] == 1
    assert "nightly" in entries[0]["id"]


def test_record_scan_avoids_collision(tmp_path):
    hdir = tmp_path / "hist"
    doc = _doc("http://127.0.0.1:8081/", [])
    p1 = record_scan(doc, hdir)
    p2 = record_scan(doc, hdir)
    assert p1 != p2
    assert len(list_scans(hdir)) == 2


def test_list_scans_filters_by_target(tmp_path):
    hdir = tmp_path / "hist"
    record_scan(_doc("http://127.0.0.1:8081/", []), hdir)
    record_scan(_doc("http://127.0.0.1:8082/", []), hdir)
    entries = list_scans(hdir, target="http://127.0.0.1:8082/")
    assert len(entries) == 1
    assert entries[0]["target"] == "http://127.0.0.1:8082/"


def test_list_scans_empty_dir_returns_empty(tmp_path):
    assert list_scans(tmp_path / "does-not-exist") == []


def test_load_scan_by_id_and_by_path(tmp_path):
    hdir = tmp_path / "hist"
    doc = _doc("http://127.0.0.1:8081/", [])
    path = record_scan(doc, hdir)
    by_id = load_scan(hdir, path.stem)
    by_path = load_scan(hdir, str(path))
    assert by_id == doc
    assert by_path == doc


def test_load_scan_missing_raises(tmp_path):
    import pytest

    with pytest.raises(FileNotFoundError):
        load_scan(tmp_path / "hist", "nope")


def test_trend_diff_introduced_and_resolved():
    older = _doc(
        "http://127.0.0.1:8081/",
        [
            {"id": "missing-hsts", "url": "http://127.0.0.1:8081/"},
            {"id": "stale-only", "url": "http://127.0.0.1:8081/old"},
        ],
        finished_at="2026-01-01T00:00:00Z",
    )
    newer = _doc(
        "http://127.0.0.1:8081/",
        [
            {"id": "missing-hsts", "url": "http://127.0.0.1:8081/"},
            {"id": "new-secret", "url": "http://127.0.0.1:8081/new"},
        ],
        finished_at="2026-02-01T00:00:00Z",
    )
    trend = trend_diff(older, newer)
    assert trend["introduced"] == [{"id": "new-secret", "url": "http://127.0.0.1:8081/new"}]
    assert trend["resolved"] == [{"id": "stale-only", "url": "http://127.0.0.1:8081/old"}]
    assert trend["unchanged_count"] == 1
    assert trend["older"]["findings"] == 2
    assert trend["newer"]["findings"] == 2


def test_render_trend_text_mentions_introduced_and_resolved():
    older = _doc("http://x/", [{"id": "a", "url": "http://x/"}])
    newer = _doc("http://x/", [{"id": "b", "url": "http://x/"}])
    text = render_trend_text(trend_diff(older, newer))
    assert "introduced (1)" in text
    assert "+ b @ http://x/" in text
    assert "resolved (1)" in text
    assert "- a @ http://x/" in text
