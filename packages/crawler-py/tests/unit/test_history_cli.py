from __future__ import annotations

import json

from shroodler.cli import build_parser


def _run(argv: list[str], capsys) -> str:
    p = build_parser()
    args = p.parse_args(argv)
    rc = args.func(args)
    assert rc == 0
    return capsys.readouterr().out


def test_history_record_and_list_roundtrip(tmp_path, capsys):
    findings = tmp_path / "scan.json"
    findings.write_text(
        json.dumps(
            {
                "target": "http://127.0.0.1:8081/",
                "scan_finished_at": "2026-01-01T00:00:00Z",
                "findings": [{"id": "missing-hsts", "url": "http://127.0.0.1:8081/"}],
            }
        ),
        encoding="utf-8",
    )
    hist_dir = tmp_path / "hist"

    out = _run(
        ["history", "record", str(findings), "--history-dir", str(hist_dir), "--label", "nightly"],
        capsys,
    )
    saved_path = out.strip()
    assert (hist_dir).is_dir()
    assert "nightly" in saved_path

    out = _run(["history", "list", "--history-dir", str(hist_dir), "--format", "json"], capsys)
    entries = json.loads(out)
    assert len(entries) == 1
    assert entries[0]["target"] == "http://127.0.0.1:8081/"


def test_trend_cli_diffs_two_recorded_scans(tmp_path, capsys):
    hist_dir = tmp_path / "hist"
    older = tmp_path / "older.json"
    newer = tmp_path / "newer.json"
    older.write_text(
        json.dumps(
            {
                "target": "http://x/",
                "scan_finished_at": "2026-01-01T00:00:00Z",
                "findings": [{"id": "a", "url": "http://x/"}],
            }
        ),
        encoding="utf-8",
    )
    newer.write_text(
        json.dumps(
            {
                "target": "http://x/",
                "scan_finished_at": "2026-02-01T00:00:00Z",
                "findings": [{"id": "b", "url": "http://x/"}],
            }
        ),
        encoding="utf-8",
    )
    older_id = _run(
        ["history", "record", str(older), "--history-dir", str(hist_dir)], capsys
    ).strip()
    newer_id = _run(
        ["history", "record", str(newer), "--history-dir", str(hist_dir)], capsys
    ).strip()
    from pathlib import Path

    older_stem = Path(older_id).stem
    newer_stem = Path(newer_id).stem

    out = _run(
        ["trend", older_stem, newer_stem, "--history-dir", str(hist_dir), "--format", "json"],
        capsys,
    )
    trend = json.loads(out)
    assert trend["introduced"] == [{"id": "b", "url": "http://x/"}]
    assert trend["resolved"] == [{"id": "a", "url": "http://x/"}]


def test_trend_cli_works_with_plain_file_paths(tmp_path, capsys):
    older = tmp_path / "older.json"
    newer = tmp_path / "newer.json"
    older.write_text(json.dumps({"target": "http://x/", "findings": []}), encoding="utf-8")
    newer.write_text(
        json.dumps({"target": "http://x/", "findings": [{"id": "a", "url": "http://x/"}]}),
        encoding="utf-8",
    )
    out = _run(["trend", str(older), str(newer)], capsys)
    assert "introduced (1)" in out
