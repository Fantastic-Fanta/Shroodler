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
    args = p.parse_args(
        ["crawl", "http://127.0.0.1:8081", "--from-capture", "sess.jsonl", "--proxy", "http://127.0.0.1:8888"]
    )
    assert args.from_capture == "sess.jsonl"
    assert args.proxy == "http://127.0.0.1:8888"
    args = p.parse_args(
        ["crawl", "http://127.0.0.1:8081", "--max-pages", "2", "--max-time", "1.5"]
    )
    assert args.max_pages == 2
    assert args.max_time == 1.5
    args = p.parse_args(["report", "out.json", "--format", "sarif"])
    assert args.format == "sarif"
    args = p.parse_args(["report", "out.json", "--format", "md"])
    assert args.format == "md"
    args = p.parse_args(["report", "out.json", "--format", "markdown"])
    assert args.format == "markdown"


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
    assert args.oob_host is None
    args = p.parse_args(
        ["payload", "scan.json", "--oob-host", "collab.example.com"]
    )
    assert args.oob_host == "collab.example.com"
    args = p.parse_args(["payload", "scan.json", "--no-csrf"])
    assert args.no_csrf is True
    args = p.parse_args(["proxy", "start", "--record", "sess.jsonl"])
    assert args.proxy_args == ["start", "--record", "sess.jsonl"]
    text = p.format_help()
    assert "payload" in text
    assert "proxy" in text
    assert "version" in text


def test_nuclei_ingest_parses():
    p = build_parser()
    args = p.parse_args(["nuclei-ingest", "a.yaml", "b.yaml", "-o", "pack.yaml"])
    assert args.templates == ["a.yaml", "b.yaml"]
    assert args.output == "pack.yaml"


def test_ingest_har_and_slither_ingest_parse():
    p = build_parser()
    args = p.parse_args(["ingest-har", "cap.har", "--target", "http://127.0.0.1/", "-o", "out.json"])
    assert args.sessions == "cap.har"
    assert args.target == "http://127.0.0.1/"
    assert args.output == "out.json"
    args = p.parse_args(["slither-ingest", "slither.json", "--target", "Vault.sol", "-o", "sc.json"])
    assert args.report == "slither.json"
    assert args.target == "Vault.sol"
    help_text = p.format_help()
    assert "ingest-har" in help_text
    assert "slither-ingest" in help_text


def test_gql_and_merge_sarif_flags_parse():
    p = build_parser()
    args = p.parse_args(
        [
            "crawl",
            "http://127.0.0.1:8081",
            "--gql-schema",
            "schema.json",
            "--gql-wordlist",
            "fields.txt",
        ]
    )
    assert args.gql_schema == ["schema.json"]
    assert args.gql_wordlist == ["fields.txt"]
    args = p.parse_args(
        ["authz-diff", "admin.json", "--gql-wordlist", "fields.txt", "--cookie", "s=1"]
    )
    assert args.gql_wordlist == ["fields.txt"]
    args = p.parse_args(
        ["report", "out.json", "--merge-sarif", "a.sarif", "--merge-sarif", "b.sarif"]
    )
    assert args.merge_sarif == ["a.sarif", "b.sarif"]


def test_authz_diff_parses():
    p = build_parser()
    args = p.parse_args(
        [
            "authz-diff",
            "admin.json",
            "-o",
            "hits.json",
            "--cookie",
            "session=user",
            "--header",
            "X-Trace: 1",
        ]
    )
    assert args.higher_crawl_json == "admin.json"
    assert args.output == "hits.json"
    assert args.cookie == ["session=user"]
    assert args.header == ["X-Trace: 1"]
    assert args.no_anon_check is False
    assert args.allow_external is False
    args = p.parse_args(["authz-diff", "admin.json", "--no-anon-check", "--allow-external"])
    assert args.no_anon_check is True
    assert args.allow_external is True
    assert "authz-diff" in p.format_help()


def test_peer_write_parses():
    p = build_parser()
    args = p.parse_args(
        [
            "peer-write",
            "play.json",
            "--from-sessions",
            "sess.jsonl",
            "--peer-cookie",
            "session=b",
            "--owner-cookie",
            "session=a",
            "--only-id",
            "10464573",
            "--rate",
            "1",
            "--allow-external",
        ]
    )
    assert args.playbook == "play.json"
    assert args.from_sessions == "sess.jsonl"
    assert args.peer_cookie == ["session=b"]
    assert args.owner_cookie == ["session=a"]
    assert args.only_id == "10464573"
    assert args.rate == 1.0
    assert args.allow_external is True
    assert args.no_csrf is False
    assert args.require_confirm is False
    args = p.parse_args(
        ["peer-write", "play.json", "--no-csrf", "--require-confirm", "--csrf-from", "http://127.0.0.1/edit"]
    )
    assert args.no_csrf is True
    assert args.require_confirm is True
    assert args.csrf_from == "http://127.0.0.1/edit"
    assert "peer-write" in p.format_help()
    args = p.parse_args(
        ["peer-write", "play.json", "--allow-unconfirmed"]
    )
    assert args.allow_unconfirmed is True


def test_session_export_parses():
    p = build_parser()
    args = p.parse_args(
        [
            "session-export",
            "--from",
            "sess.jsonl",
            "--origin",
            "https://app.example",
            "-o",
            "state.json",
        ]
    )
    assert args.source == "sess.jsonl"
    assert args.origin == "https://app.example"
    assert args.output == "state.json"
    assert "session-export" in p.format_help()


def test_js_routes_parses():
    p = build_parser()
    args = p.parse_args(["js-routes", "app.js", "-o", "routes.json"])
    assert args.js_file == "app.js"
    assert args.output == "routes.json"
    assert "js-routes" in p.format_help()


def test_paced_fetch_parses():
    p = build_parser()
    args = p.parse_args(
        [
            "paced-fetch",
            "--url",
            "http://127.0.0.1/a",
            "--urls-file",
            "urls.txt",
            "--rate",
            "1",
            "--user-agent-suffix",
            "Bugcrowd-handle",
        ]
    )
    assert args.url == ["http://127.0.0.1/a"]
    assert args.urls_file == "urls.txt"
    assert args.rate == 1.0
    assert args.user_agent_suffix == "Bugcrowd-handle"
    assert args.method == "GET"
    assert "paced-fetch" in p.format_help()


def test_plugin_and_mcp_server_flags_parse():
    p = build_parser()
    args = p.parse_args(["crawl", "http://127.0.0.1:8081", "--plugin", "./plug"])
    assert args.plugin == ["./plug"]
    args = p.parse_args(["payload", "scan.json", "--plugin", "./plug", "--pack", "x.yaml"])
    assert args.plugin == ["./plug"]
    args = p.parse_args(["mcp-server", "--list-tools"])
    assert args.list_tools is True
    mcp_help = p._subparsers._group_actions[0].choices["mcp-server"].format_help()
    assert "scan_route" in mcp_help
    assert "check_idor" in mcp_help
    assert "peer_write" in mcp_help
    assert "session_export" in mcp_help
    assert "extract_js_routes" in mcp_help
    assert "paced_fetch" in mcp_help
    assert "reverify_fix" in mcp_help
    assert "program_state" in mcp_help
    assert "coverage_gaps" in mcp_help
    assert "--list-tools" in mcp_help


def test_reauth_and_program_flags_parse():
    p = build_parser()
    args = p.parse_args(
        [
            "crawl",
            "http://127.0.0.1:8081",
            "--login-recipe",
            "login.json",
            "--reauth-max-retries",
            "5",
            "--program",
            "etoro-bugcrowd",
        ]
    )
    assert args.reauth_max_retries == 5
    assert args.program == "etoro-bugcrowd"
    args = p.parse_args(["authz-diff", "admin.json", "--program", "lab"])
    assert args.program == "lab"
    args = p.parse_args(
        ["peer-write", "play.json", "--program", "lab", "--from-program", "lab"]
    )
    assert args.program == "lab"
    assert args.from_program == "lab"
    args = p.parse_args(["program", "init", "etoro-bugcrowd", "--scope-file", "scope.txt"])
    assert args.slug == "etoro-bugcrowd"
    assert args.scope_file == "scope.txt"
    args = p.parse_args(["program", "status", "etoro-bugcrowd"])
    assert args.func.__name__ == "cmd_program_status"
    args = p.parse_args(["program", "merge", "lab", "out.json"])
    assert args.crawl_json == "out.json"
    args = p.parse_args(
        ["program", "add-session", "lab", "owner.json", "--label", "owner", "--expires", "2026-12-01"]
    )
    assert args.path == "owner.json"
    assert args.label == "owner"
    assert args.expires == "2026-12-01"
    assert "program" in p.format_help()
