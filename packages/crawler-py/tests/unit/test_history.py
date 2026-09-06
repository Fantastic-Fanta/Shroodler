from __future__ import annotations

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


def test_trend_diff_detects_severity_increase_on_same_key():
    older = _doc(
        "http://x/",
        [{"id": "missing-hsts", "url": "http://x/", "severity": "low"}],
        finished_at="2026-01-01T00:00:00Z",
    )
    newer = _doc(
        "http://x/",
        [{"id": "missing-hsts", "url": "http://x/", "severity": "medium"}],
        finished_at="2026-02-01T00:00:00Z",
    )
    trend = trend_diff(older, newer)
    assert trend["severity_increased"] == [
        {"id": "missing-hsts", "url": "http://x/", "from": "low", "to": "medium"}
    ]
    # Same (id, url) key both before and after -- must not also be
    # reported as introduced/resolved.
    assert trend["introduced"] == []
    assert trend["resolved"] == []


def test_trend_diff_does_not_flag_unchanged_or_decreased_severity():
    same = trend_diff(
        _doc("http://x/", [{"id": "a", "url": "http://x/", "severity": "medium"}]),
        _doc("http://x/", [{"id": "a", "url": "http://x/", "severity": "medium"}]),
    )
    assert same["severity_increased"] == []

    decreased = trend_diff(
        _doc("http://x/", [{"id": "a", "url": "http://x/", "severity": "high"}]),
        _doc("http://x/", [{"id": "a", "url": "http://x/", "severity": "low"}]),
    )
    assert decreased["severity_increased"] == []


def test_render_trend_text_mentions_severity_increase():
    older = _doc("http://x/", [{"id": "a", "url": "http://x/", "severity": "low"}])
    newer = _doc("http://x/", [{"id": "a", "url": "http://x/", "severity": "critical"}])
    text = render_trend_text(trend_diff(older, newer))
    assert "severity increased (1)" in text
    assert "! a @ http://x/: low -> critical" in text


def test_cli_trend_gate_on_severity_increase(tmp_path):
    import json

    import pytest

    from shroodler.cli import main

    hdir = tmp_path / "hist"
    older = _doc("http://x/", [{"id": "a", "url": "http://x/", "severity": "low"}])
    newer = _doc("http://x/", [{"id": "a", "url": "http://x/", "severity": "critical"}])
    older_path = tmp_path / "older.json"
    newer_path = tmp_path / "newer.json"
    older_path.write_text(json.dumps(older), encoding="utf-8")
    newer_path.write_text(json.dumps(newer), encoding="utf-8")
    with pytest.raises(SystemExit) as ex:
        main(
            [
                "trend",
                str(older_path),
                str(newer_path),
                "--history-dir",
                str(hdir),
                "--gate-on-severity-increase",
            ]
        )
    assert ex.value.code == 1


def test_cli_trend_gate_on_severity_increase_clean_exits_zero(tmp_path):
    import json

    import pytest

    from shroodler.cli import main

    hdir = tmp_path / "hist"
    doc = _doc("http://x/", [{"id": "a", "url": "http://x/", "severity": "low"}])
    older_path = tmp_path / "older.json"
    newer_path = tmp_path / "newer.json"
    older_path.write_text(json.dumps(doc), encoding="utf-8")
    newer_path.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(SystemExit) as ex:
        main(
            [
                "trend",
                str(older_path),
                str(newer_path),
                "--history-dir",
                str(hdir),
                "--gate-on-severity-increase",
            ]
        )
    assert ex.value.code == 0


def test_trend_diff_unrecognized_severity_does_not_fabricate_an_increase():
    # Regression test: an unrecognized severity string in the OLDER scan
    # (a corrupted/hand-edited history file, or a future severity level
    # this table doesn't know yet) must not default to "as if info" and
    # make every real severity in the newer scan look like an increase.
    older = _doc("http://x/", [{"id": "a", "url": "http://x/", "severity": "Weird"}])
    newer = _doc("http://x/", [{"id": "a", "url": "http://x/", "severity": "low"}])
    assert trend_diff(older, newer)["severity_increased"] == []

    # Same check the other direction (unrecognized in the newer scan).
    older2 = _doc("http://x/", [{"id": "a", "url": "http://x/", "severity": "critical"}])
    newer2 = _doc("http://x/", [{"id": "a", "url": "http://x/", "severity": "Weird"}])
    assert trend_diff(older2, newer2)["severity_increased"] == []


def _doc_with_pages(target: str, pages: list[str], challenged: list[str]) -> dict:
    return {
        "target": target,
        "scan_finished_at": "2026-01-01T00:00:00Z",
        "pages": [{"url": u} for u in pages],
        "findings": [
            {
                "id": "waf-challenge-detected",
                "severity": "info",
                "category": "waf-challenge",
                "url": u,
                "description": "d",
                "evidence": None,
            }
            for u in challenged
        ],
    }


def test_cli_trend_gate_on_waf_coverage_drop(tmp_path):
    import json

    import pytest

    from shroodler.cli import main

    hdir = tmp_path / "hist"
    pages = ["http://x/a", "http://x/b"]
    older = _doc_with_pages("http://x/", pages, pages)  # 100% coverage
    newer = _doc_with_pages("http://x/", pages, [])  # 0% coverage
    older_path = tmp_path / "older.json"
    newer_path = tmp_path / "newer.json"
    older_path.write_text(json.dumps(older), encoding="utf-8")
    newer_path.write_text(json.dumps(newer), encoding="utf-8")
    with pytest.raises(SystemExit) as ex:
        main(
            [
                "trend",
                str(older_path),
                str(newer_path),
                "--history-dir",
                str(hdir),
                "--gate-on-waf-coverage-drop",
            ]
        )
    assert ex.value.code == 1


def test_cli_trend_gate_on_waf_coverage_drop_skips_mismatched_page_counts(tmp_path, capsys):
    import json

    import pytest

    from shroodler.cli import main

    hdir = tmp_path / "hist"
    older_pages = [f"http://x/{i}" for i in range(5)]
    newer_pages = [f"http://x/{i}" for i in range(50)]
    older = _doc_with_pages("http://x/", older_pages, older_pages)  # 100%, 5 pages
    newer = _doc_with_pages("http://x/", newer_pages, newer_pages[:25])  # 50%, 50 pages
    older_path = tmp_path / "older.json"
    newer_path = tmp_path / "newer.json"
    older_path.write_text(json.dumps(older), encoding="utf-8")
    newer_path.write_text(json.dumps(newer), encoding="utf-8")
    with pytest.raises(SystemExit) as ex:
        main(
            [
                "trend",
                str(older_path),
                str(newer_path),
                "--history-dir",
                str(hdir),
                "--gate-on-waf-coverage-drop",
            ]
        )
    # Not gated: page counts (5 vs 50) differ by more than 2x, so this
    # low-confidence comparison doesn't fail the build by default.
    assert ex.value.code == 0
    assert "NOT gated" in capsys.readouterr().err


def test_cli_trend_gate_even_if_page_count_mismatch_overrides(tmp_path):
    import json

    import pytest

    from shroodler.cli import main

    hdir = tmp_path / "hist"
    older_pages = [f"http://x/{i}" for i in range(5)]
    newer_pages = [f"http://x/{i}" for i in range(50)]
    older = _doc_with_pages("http://x/", older_pages, older_pages)
    newer = _doc_with_pages("http://x/", newer_pages, newer_pages[:25])
    older_path = tmp_path / "older.json"
    newer_path = tmp_path / "newer.json"
    older_path.write_text(json.dumps(older), encoding="utf-8")
    newer_path.write_text(json.dumps(newer), encoding="utf-8")
    with pytest.raises(SystemExit) as ex:
        main(
            [
                "trend",
                str(older_path),
                str(newer_path),
                "--history-dir",
                str(hdir),
                "--gate-on-waf-coverage-drop",
                "--gate-even-if-page-count-mismatch",
            ]
        )
    assert ex.value.code == 1


def test_cli_trend_gate_even_if_page_count_mismatch_alone_has_no_effect(tmp_path):
    # Passing --gate-even-if-page-count-mismatch WITHOUT --gate-on-waf-
    # coverage-drop must not gate on anything by itself -- it only
    # modifies the other flag's behavior.
    import json

    import pytest

    from shroodler.cli import main

    hdir = tmp_path / "hist"
    older_pages = [f"http://x/{i}" for i in range(5)]
    newer_pages = [f"http://x/{i}" for i in range(50)]
    older = _doc_with_pages("http://x/", older_pages, older_pages)
    newer = _doc_with_pages("http://x/", newer_pages, newer_pages[:25])
    older_path = tmp_path / "older.json"
    newer_path = tmp_path / "newer.json"
    older_path.write_text(json.dumps(older), encoding="utf-8")
    newer_path.write_text(json.dumps(newer), encoding="utf-8")
    with pytest.raises(SystemExit) as ex:
        main(
            [
                "trend",
                str(older_path),
                str(newer_path),
                "--history-dir",
                str(hdir),
                "--gate-even-if-page-count-mismatch",
            ]
        )
    assert ex.value.code == 0


def test_cli_trend_json_includes_waf_coverage_regression_key(tmp_path, capsys):
    import json

    import pytest

    from shroodler.cli import main

    hdir = tmp_path / "hist"
    pages = ["http://x/a", "http://x/b"]
    older = _doc_with_pages("http://x/", pages, pages)
    newer = _doc_with_pages("http://x/", pages, pages)  # no drop
    older_path = tmp_path / "older.json"
    newer_path = tmp_path / "newer.json"
    older_path.write_text(json.dumps(older), encoding="utf-8")
    newer_path.write_text(json.dumps(newer), encoding="utf-8")
    with pytest.raises(SystemExit) as ex:
        main(
            [
                "trend",
                str(older_path),
                str(newer_path),
                "--history-dir",
                str(hdir),
                "--format",
                "json",
            ]
        )
    assert ex.value.code == 0
    out = json.loads(capsys.readouterr().out)
    assert out["waf_coverage_regression"] is None
