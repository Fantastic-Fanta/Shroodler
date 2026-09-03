from __future__ import annotations

from shroodler.cli import build_parser
from shroodler.config import load_rc


def test_cli_has_format_flags():
    p = build_parser()
    args = p.parse_args(["crawl", "http://127.0.0.1:8081", "--format", "csv"])
    assert args.format == "csv"
    args = p.parse_args(
        [
            "crawl",
            "http://127.0.0.1:8081",
            "--cookie",
            "a=b",
            "--cookie-jar",
            "jar.json",
            "--login-recipe",
            "login.json",
            "--storage-state",
            "state.json",
        ]
    )
    assert args.cookie == ["a=b"]
    assert args.cookie_jar == "jar.json"
    assert args.login_recipe == "login.json"
    assert args.storage_state == "state.json"
    args = p.parse_args(
        [
            "crawl",
            "http://127.0.0.1:8081",
            "--header",
            "X-Lab-Auth: open",
            "--header",
            "X-Trace: 1",
            "--cookie",
            "lab_auth=open",
        ]
    )
    assert args.header == ["X-Lab-Auth: open", "X-Trace: 1"]
    assert args.cookie == ["lab_auth=open"]
    args = p.parse_args(["crawl", "http://127.0.0.1:8081", "--no-sitemap"])
    assert args.no_sitemap is True


def test_load_rc_missing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("shroodler.config.Path.home", lambda: tmp_path)
    assert load_rc() == {}


def test_expected_command_parses():
    p = build_parser()
    args = p.parse_args(
        ["expected", "scan.json", "--output", "expected_findings.json", "--name", "lab"]
    )
    assert args.findings == "scan.json"
    assert args.output == "expected_findings.json"
    assert args.name == "lab"
    joined = p._subparsers._group_actions[0].choices["expected"].format_help()
    assert "expected_not_found" in joined
    assert "negatives" in joined


def test_payload_and_proxy_parse():
    p = build_parser()
    args = p.parse_args(["payload", "scan.json", "-o", "hits.json", "--pack", "extra.yaml"])
    assert args.crawl_json == "scan.json"
    assert args.output == "hits.json"
    assert args.pack == ["extra.yaml"]
    args = p.parse_args(["proxy", "start", "--record", "sess.jsonl"])
    assert args.proxy_args == ["start", "--record", "sess.jsonl"]
    text = p.format_help()
    assert "payload" in text
    assert "proxy" in text
    assert "version" in text
