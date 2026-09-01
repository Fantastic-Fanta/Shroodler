from __future__ import annotations

from shroodler.cli import build_parser
from shroodler.config import load_rc


def test_cli_has_format_flags():
    p = build_parser()
    args = p.parse_args(["crawl", "http://127.0.0.1:8081", "--format", "csv"])
    assert args.format == "csv"


def test_load_rc_missing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("shroodler.config.Path.home", lambda: tmp_path)
    assert load_rc() == {}
