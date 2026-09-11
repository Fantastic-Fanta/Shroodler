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
    args = p.parse_args(["report", "out.json", "--format", "pentest"])
    assert args.format == "pentest"
    args = p.parse_args(["report", "out.json", "--format", "pentest-html"])
    assert args.format == "pentest-html"


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
    args = p.parse_args(
        ["ingest-har", "cap.har", "--target", "http://127.0.0.1/", "-o", "out.json"]
    )
    assert args.sessions == "cap.har"
    assert args.target == "http://127.0.0.1/"
    assert args.output == "out.json"
    args = p.parse_args(
        ["slither-ingest", "slither.json", "--target", "Vault.sol", "-o", "sc.json"]
    )
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
    assert "run_agent" in mcp_help
    assert "discover_scope" in mcp_help
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
        [
            "program",
            "add-session",
            "lab",
            "owner.json",
            "--label",
            "owner",
            "--expires",
            "2026-12-01",
        ]
    )
    assert args.path == "owner.json"
    assert args.label == "owner"
    assert args.expires == "2026-12-01"
    assert "program" in p.format_help()


def test_agent_flags_parse():
    p = build_parser()
    args = p.parse_args(
        [
            "agent",
            "--program",
            "lab",
            "--target",
            "http://127.0.0.1/",
            "--max-iterations",
            "4",
            "--max-pages-per-crawl",
            "12",
            "--login-recipe",
            "login.json",
            "--reauth-max-retries",
            "5",
            "--higher-priv-jar",
            "high.json",
            "--lower-priv-jar",
            "low.json",
            "--owner-cookie",
            "session=a",
            "--peer-cookie",
            "session=b",
            "--dry-run",
            "--llm-triage",
            "--run-discovery",
            "--write-authz-spec",
            "writes.json",
        ]
    )
    assert args.func.__name__ == "cmd_agent"
    assert args.program == "lab"
    assert args.target == "http://127.0.0.1/"
    assert args.max_iterations == 4
    assert args.max_pages_per_crawl == 12
    assert args.login_recipe == "login.json"
    assert args.reauth_max_retries == 5
    assert args.higher_priv_jar == "high.json"
    assert args.lower_priv_jar == "low.json"
    assert args.owner_cookie == "session=a"
    assert args.peer_cookie == "session=b"
    assert args.dry_run is True
    assert args.llm_triage is True
    assert args.run_discovery is True
    assert args.write_authz_spec == "writes.json"
    assert args.run_probes is False
    assert args.reprobe is False
    assert "agent" in p.format_help()

    args = p.parse_args(
        [
            "agent",
            "--program",
            "lab",
            "--target",
            "http://127.0.0.1/",
            "--run-probes",
        ]
    )
    assert args.run_probes is True
    assert args.reprobe is False

    args = p.parse_args(
        [
            "agent",
            "--program",
            "lab",
            "--target",
            "http://127.0.0.1/",
            "--run-probes",
            "--reprobe",
        ]
    )
    assert args.run_probes is True
    assert args.reprobe is True

    args = p.parse_args(
        [
            "agent",
            "--program",
            "lab",
            "--target",
            "http://127.0.0.1/",
            "--no-openapi",
        ]
    )
    assert args.no_openapi is True
    assert args.run_probes is False

    args = p.parse_args(
        [
            "agent",
            "--program",
            "lab",
            "--target",
            "http://127.0.0.1/",
            "--run-probes",
            "--no-ssrf",
            "--no-open-redirect",
            "--no-host-header",
            "--no-ssti",
            "--no-xxe",
            "--no-graphql",
            "--no-auto-register",
        ]
    )
    assert args.run_probes is True
    assert args.no_ssrf is True
    assert args.no_open_redirect is True
    assert args.no_host_header is True
    assert args.no_ssti is True
    assert args.no_xxe is True
    assert args.no_graphql is True
    assert args.no_auto_register is True

    args = p.parse_args(
        [
            "agent",
            "--program",
            "lab",
            "--target",
            "http://127.0.0.1/",
            "--run-probes",
            "--dom-xss",
            "--no-crlf",
            "--no-prototype-pollution",
            "--no-content-discovery",
            "--no-tls-check",
            "--no-rate-limit-check",
            "--no-mass-assignment",
            "--smuggling",
            "--no-websocket",
            "--allow-external",
            "--scope-file",
            "scope.json",
        ]
    )
    assert args.dom_xss is True
    assert args.no_crlf is True
    assert args.no_prototype_pollution is True
    assert args.no_content_discovery is True
    assert args.no_tls_check is True
    assert args.no_rate_limit_check is True
    assert args.no_mass_assignment is True
    assert args.smuggling is True
    assert args.no_websocket is True
    assert args.allow_external is True
    assert args.scope_file == "scope.json"

    args = p.parse_args(
        [
            "agent",
            "--program",
            "lab",
            "--target",
            "http://127.0.0.1/",
            "--run-diff",
            "--llm-business-logic",
            "--chain-spec",
            "a.json",
            "--chain-spec",
            "b.json",
        ]
    )
    assert args.run_diff is True
    assert args.llm_business_logic is True
    assert args.chain_spec == ["a.json", "b.json"]

    args = p.parse_args(
        [
            "agent",
            "--program",
            "lab",
            "--target",
            "http://127.0.0.1/",
            "--llm-agent",
            "--llm-agent-model",
            "opus",
            "--llm-agent-max-cost",
            "1.5",
        ]
    )
    assert args.llm_agent is True
    assert args.llm_agent_model == "opus"
    assert args.llm_agent_max_cost == 1.5
    args = p.parse_args(
        [
            "agent",
            "--program",
            "lab",
            "--target",
            "http://127.0.0.1/",
        ]
    )
    assert args.llm_agent is False
    assert args.llm_agent_model == "deepseek-chat"
    assert args.llm_agent_max_cost == 5.0


def test_discover_flags_parse():
    p = build_parser()
    args = p.parse_args(
        [
            "discover",
            "--program",
            "lab",
            "--target",
            "https://api.example.com/",
            "--max-subdomains",
            "50",
            "--probe-workers",
            "4",
            "--skip-crtsh",
            "--skip-js-surface",
            "--dry-run",
        ]
    )
    assert args.func.__name__ == "cmd_discover"
    assert args.program == "lab"
    assert args.target == "https://api.example.com/"
    assert args.max_subdomains == 50
    assert args.probe_workers == 4
    assert args.skip_crtsh is True
    assert args.skip_js_surface is True
    assert args.dry_run is True
    assert "discover" in p.format_help()


def test_engagement_and_suppress_flags_parse():
    p = build_parser()
    args = p.parse_args(
        ["suppress", "--program", "lab", "--id", "sqli", "--url", "*", "--reason", "fp"]
    )
    assert args.func.__name__ == "cmd_suppress"
    assert args.finding_id == "sqli"
    args = p.parse_args(["engagement-history", "--program", "lab"])
    assert args.func.__name__ == "cmd_engagement_history"
    args = p.parse_args(["engagement-diff", "--program", "lab"])
    assert args.func.__name__ == "cmd_engagement_diff"
    # Existing history and suppress subcommands still parse.
    args = p.parse_args(["history", "list"])
    assert args.func.__name__ == "cmd_history_list"
    args = p.parse_args(["suppress", "expiring"])
    assert args.func.__name__ == "cmd_suppress_expiring"


def test_dedup_and_ci_template_and_program_scope_parse():
    p = build_parser()
    args = p.parse_args(["dedup", "findings.json", "--output", "out.json"])
    assert args.func.__name__ == "cmd_dedup"
    assert args.findings == "findings.json"
    assert args.output == "out.json"
    args = p.parse_args(
        [
            "ci-template",
            "--platform",
            "github",
            "--program",
            "lab",
            "--target",
            "http://127.0.0.1/",
        ]
    )
    assert args.func.__name__ == "cmd_ci_template"
    assert args.platform == "github"
    args = p.parse_args(
        [
            "program",
            "scope",
            "--program",
            "lab",
            "--include",
            "*.example.com",
            "--exclude",
            "cdn.example.com",
        ]
    )
    assert args.func.__name__ == "cmd_program_scope"
    assert args.program == "lab"
    assert args.include == ["*.example.com"]
    args = p.parse_args(["report", "out.json", "--no-dedup"])
    assert args.dedup is False
    args = p.parse_args(["report", "out.json"])
    assert args.dedup is True


def test_agent_no_waf_detect_flag():
    p = build_parser()
    args = p.parse_args(
        [
            "agent",
            "--program",
            "lab",
            "--target",
            "http://127.0.0.1/",
            "--no-waf-detect",
        ]
    )
    assert args.no_waf_detect is True
    args = p.parse_args(
        ["agent", "--program", "lab", "--target", "http://127.0.0.1/"]
    )
    assert args.no_waf_detect is False
    agent_help = p._subparsers._group_actions[0].choices["agent"].format_help()
    assert "--no-waf-detect" in agent_help


def test_agent_no_js_analysis_flag():
    p = build_parser()
    args = p.parse_args(
        [
            "agent",
            "--program",
            "lab",
            "--target",
            "http://127.0.0.1/",
            "--no-js-analysis",
        ]
    )
    assert args.no_js_analysis is True
    args = p.parse_args(
        ["agent", "--program", "lab", "--target", "http://127.0.0.1/"]
    )
    assert args.no_js_analysis is False


def test_agent_peer_recipe_flag():
    p = build_parser()
    args = p.parse_args(
        [
            "agent",
            "--program",
            "lab",
            "--target",
            "http://127.0.0.1/",
            "--login-recipe",
            "owner.json",
            "--peer-recipe",
            "peer.json",
        ]
    )
    assert args.peer_recipe == "peer.json"
    assert args.login_recipe == "owner.json"
    agent_help = p._subparsers._group_actions[0].choices["agent"].format_help()
    assert "--peer-recipe" in agent_help


def test_triage_findings_and_submit_format_parse():
    p = build_parser()
    args = p.parse_args(
        ["triage-findings", "state.json", "--min-score", "40", "--format", "json"]
    )
    assert args.command == "triage-findings"
    assert args.min_score == 40
    assert args.format == "json"
    args = p.parse_args(["report", "out.json", "--format", "submit"])
    assert args.format == "submit"


def test_llm_provider_deepseek_flags_parse_to_agent_config(monkeypatch):
    from types import SimpleNamespace

    from shroodler.agent import AgentConfig
    from shroodler.cli import cmd_agent

    captured: dict = {}

    def fake_run(config):
        captured["config"] = config
        return SimpleNamespace(iterations=0, confirmed=0, state_path="", errors=[])

    monkeypatch.setattr("shroodler.agent.run_agent", fake_run)
    p = build_parser()
    args = p.parse_args(
        [
            "agent",
            "--program",
            "lab",
            "--target",
            "http://127.0.0.1/",
            "--llm-provider",
            "deepseek",
            "--llm-model",
            "deepseek-chat",
        ]
    )
    assert args.llm_provider == "deepseek"
    assert args.llm_agent_model == "deepseek-chat"
    assert cmd_agent(args) == 0
    cfg = captured["config"]
    assert isinstance(cfg, AgentConfig)
    assert cfg.llm_provider == "deepseek"
    assert cfg.llm_agent_model == "deepseek-chat"


def test_cmd_agent_deepseek_requires_deepseek_key(monkeypatch, capsys):
    from shroodler.cli import cmd_agent

    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    called = {"n": 0}

    def boom(*_a, **_k):
        called["n"] += 1
        raise AssertionError("run_agent must not start")

    monkeypatch.setattr("shroodler.agent.run_agent", boom)
    p = build_parser()
    args = p.parse_args(
        [
            "agent",
            "--program",
            "lab",
            "--target",
            "http://127.0.0.1/",
            "--llm-agent",
            "--llm-provider",
            "deepseek",
        ]
    )
    assert cmd_agent(args) == 2
    assert called["n"] == 0
    err = capsys.readouterr().err
    assert "DEEPSEEK_API_KEY" in err
    assert "ANTHROPIC_API_KEY" not in err


def test_agent_oob_flags_parse(monkeypatch):
    from types import SimpleNamespace

    from shroodler.cli import cmd_agent

    p = build_parser()
    args = p.parse_args(
        [
            "agent",
            "--program",
            "lab",
            "--target",
            "http://127.0.0.1/",
            "--oob",
            "--oob-listen",
            "127.0.0.1:0",
            "--oob-public-url",
            "http://example.invalid",
        ]
    )
    assert args.func.__name__ == "cmd_agent"
    assert args.oob is True
    assert args.oob_listen == "127.0.0.1:0"
    assert args.oob_public_url == "http://example.invalid"
    agent_help = p._subparsers._group_actions[0].choices["agent"].format_help()
    assert "--oob" in agent_help
    assert "--oob-listen" in agent_help
    assert "--oob-public-url" in agent_help

    captured: dict = {}

    def fake_run(config):
        captured["config"] = config
        return SimpleNamespace(iterations=0, confirmed=0, state_path="", errors=[])

    monkeypatch.setattr("shroodler.agent.run_agent", fake_run)
    assert cmd_agent(args) == 0
    config = captured["config"]
    assert config.oob is True
    assert config.oob_listen == "127.0.0.1:0"
    assert config.oob_public_url == "http://example.invalid"

    default_args = p.parse_args(
        ["agent", "--program", "lab", "--target", "http://127.0.0.1/"]
    )
    assert default_args.oob is False




def test_robots_flags_resolution():
    import argparse

    from shroodler.cli import _robots_flags

    def ns(**kw):
        n = argparse.Namespace()
        for k, v in kw.items():
            setattr(n, k, v)
        return n

    assert _robots_flags(ns(robots="respect", ignore_robots=False)) == (False, False)
    assert _robots_flags(ns(robots="ignore", ignore_robots=False)) == (True, False)
    assert _robots_flags(ns(robots="harvest", ignore_robots=False)) == (True, True)
    # Legacy --ignore-robots with no --robots still bypasses.
    assert _robots_flags(ns(robots=None, ignore_robots=True)) == (True, False)
    # Nothing set: honor robots.
    assert _robots_flags(ns(robots=None, ignore_robots=False)) == (False, False)


def test_profile_sets_robots_default():
    from shroodler.cli import _apply_profile, build_parser

    parser = build_parser()
    _apply_profile(parser, "aggressive")
    args = parser.parse_args(["crawl", "http://127.0.0.1/"])
    assert args.robots == "harvest"

    parser2 = build_parser()
    _apply_profile(parser2, "safe")
    args2 = parser2.parse_args(["crawl", "http://127.0.0.1/"])
    assert args2.robots == "respect"
