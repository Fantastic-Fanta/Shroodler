from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from shroodler.agent import (
    _TOOL_NOISE_IDS,
    AgentConfig,
    AuthzDiffAction,
    AutoRegisterAction,
    ContentDiscoverAction,
    CrawlAction,
    OpenApiDiscoverAction,
    OpenApiProbeAction,
    PeerWriteAction,
    ProbeAction,
    ReportAction,
    TLSCheckAction,
    WriteAuthzAction,
    _auth_header_for_diff,
    _confirmed_findings,
    _untested_probe_urls,
    decide_next_action,
    execute_action,
    run_agent,
)
from shroodler.models import Finding
from shroodler.pacer import Pacer
from shroodler.program import ProgramState, load, save


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _old_iso() -> str:
    ts = datetime.now(timezone.utc) - timedelta(hours=48)
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


def _config(**kwargs) -> AgentConfig:
    defaults = {
        "program": "lab",
        "target": "http://127.0.0.1/",
        "max_iterations": 3,
        "max_pages_per_crawl": 10,
        "dry_run": True,
        "run_openapi_discovery": False,
        "run_openapi_probes": False,
        "run_tls_check": False,
        "run_content_discovery": False,
    }
    defaults.update(kwargs)
    return AgentConfig(**defaults)


def _endpoint(last_seen: str = "", tested_authz: bool = False, tested_peer: bool = False) -> dict:
    return {
        "last_seen": last_seen,
        "tested_authz": tested_authz,
        "tested_peer_write": tested_peer,
        "tested_payload": False,
    }


def test_decide_crawl_when_gaps_exist():
    state = ProgramState(
        slug="lab",
        endpoints={
            "http://127.0.0.1/api/a": _endpoint(last_seen=""),
            "http://127.0.0.1/api/b": _endpoint(last_seen=_old_iso()),
        },
    )
    action = decide_next_action(state, _config())
    assert isinstance(action, CrawlAction)
    assert "http://127.0.0.1/api/a" in action.urls
    assert "http://127.0.0.1/api/b" in action.urls


def test_decide_authz_when_crawl_done():
    state = ProgramState(
        slug="lab",
        endpoints={
            "http://127.0.0.1/api/a": _endpoint(last_seen=_now_iso(), tested_authz=False),
        },
    )
    action = decide_next_action(
        state,
        _config(higher_priv_jar="/tmp/higher.json", lower_priv_jar="/tmp/lower.json"),
    )
    assert isinstance(action, AuthzDiffAction)
    assert action.urls == ["http://127.0.0.1/api/a"]


def test_decide_peer_write_when_object_ids_present():
    state = ProgramState(
        slug="lab",
        endpoints={
            "http://127.0.0.1/api/users/1": _endpoint(
                last_seen=_now_iso(), tested_authz=True, tested_peer=False
            ),
        },
        object_ids={"/api/users/{id}": ["1"]},
    )
    action = decide_next_action(
        state,
        _config(owner_cookie="session=owner", peer_cookie="session=peer"),
    )
    assert isinstance(action, PeerWriteAction)
    assert "1" in action.object_ids


def test_decide_none_when_nothing_left():
    state = ProgramState(
        slug="lab",
        endpoints={
            "http://127.0.0.1/api/a": _endpoint(
                last_seen=_now_iso(), tested_authz=True, tested_peer=True
            ),
        },
    )
    action = decide_next_action(state, _config())
    assert action is None


def test_dry_run_makes_no_requests(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    http_calls: list[str] = []

    class BoomClient:
        def __init__(self, *args, **kwargs):
            http_calls.append("client")
            raise AssertionError("httpx.Client must not be constructed in dry-run")

    def boom_crawl(*args, **kwargs):
        http_calls.append("crawl")
        raise AssertionError("crawl_url must not be called in dry-run")

    monkeypatch.setattr("httpx.Client", BoomClient)
    monkeypatch.setattr("shroodler.crawler.crawl_url", boom_crawl)
    load("lab")
    result = run_agent(
        _config(program="lab", target="http://127.0.0.1/", dry_run=True, max_iterations=2)
    )
    assert http_calls == []
    assert result.iterations >= 1
    assert result.log[0]["dry_run"] is True
    assert result.log[0]["action"] == "CrawlAction"


def test_scope_check_rejects_out_of_scope_target(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    state = load("lab")
    state.scope_urls = ["https://in-scope.example/"]
    save(state)
    with pytest.raises(ValueError, match="not in program"):
        run_agent(
            _config(
                program="lab",
                target="https://evil.example/",
                dry_run=True,
            )
        )


def test_loop_stops_at_max_iterations(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    load("lab")
    monkeypatch.setattr(
        "shroodler.agent.decide_next_action",
        lambda state, config, *args, **kwargs: CrawlAction(urls=["http://127.0.0.1/"]),
    )
    result = run_agent(
        _config(program="lab", target="http://127.0.0.1/", dry_run=True, max_iterations=3)
    )
    assert result.iterations == 3
    assert [e["action"] for e in result.log] == ["CrawlAction"] * 3


def test_state_saved_after_each_action(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    load("lab")
    saves: list[str] = []

    def fake_save(state):
        saves.append(state.slug)
        return Path("/dev/null")

    monkeypatch.setattr("shroodler.agent.program.save", fake_save)
    monkeypatch.setattr(
        "shroodler.agent.decide_next_action",
        lambda state, config, *args, **kwargs: CrawlAction(urls=["http://127.0.0.1/"]),
    )
    monkeypatch.setattr(
        "shroodler.agent.execute_action",
        lambda action, state, config, pacer=None: {
            "pages_crawled": 0,
            "findings_added": 0,
        },
    )
    result = run_agent(
        _config(program="lab", target="http://127.0.0.1/", dry_run=False, max_iterations=4)
    )
    assert result.iterations == 4
    assert len(saves) == 5


def test_decide_skips_out_of_origin_crawl_urls():
    state = ProgramState(
        slug="lab",
        endpoints={
            "https://evil.example/x": _endpoint(last_seen=""),
            "http://127.0.0.1/ok": _endpoint(last_seen=""),
        },
    )
    action = decide_next_action(state, _config())
    assert isinstance(action, CrawlAction)
    assert action.urls == ["http://127.0.0.1/ok"]


def test_execute_errors_are_logged_and_loop_continues(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    load("lab")
    calls = {"n": 0}

    def flaky(action, state, config, pacer=None):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("boom")
        return {"pages_crawled": 0, "findings_added": 0}

    monkeypatch.setattr(
        "shroodler.agent.decide_next_action",
        lambda state, config, *args, **kwargs: CrawlAction(urls=["http://127.0.0.1/"]),
    )
    monkeypatch.setattr("shroodler.agent.execute_action", flaky)
    monkeypatch.setattr("shroodler.agent.program.save", lambda state: Path("/dev/null"))
    result = run_agent(
        _config(program="lab", target="http://127.0.0.1/", dry_run=False, max_iterations=3)
    )
    assert result.iterations == 3
    assert result.log[0].get("error")
    assert "result" in result.log[1]
    assert len(result.errors) == 1


def test_decide_report_when_confirmed_and_queue_empty():
    state = ProgramState(
        slug="lab",
        endpoints={
            "http://127.0.0.1/api/a": _endpoint(
                last_seen=_now_iso(), tested_authz=True, tested_peer=True
            ),
        },
        findings=[
            Finding(
                id="authz-broken-access-control",
                severity="high",
                category="auth",
                url="http://127.0.0.1/api/a",
                description="confirmed lead",
                confidence="confirmed",
            )
        ],
    )
    action = decide_next_action(state, _config())
    assert isinstance(action, ReportAction)


def test_execute_crawl_merges_mocked_result(monkeypatch):
    class FakeResult:
        def to_dict(self):
            return {
                "pages": [{"url": "http://127.0.0.1/api/a", "status_code": 200}],
                "findings": [
                    {
                        "id": "missing-hsts",
                        "severity": "medium",
                        "category": "header",
                        "url": "http://127.0.0.1/api/a",
                        "description": "no hsts",
                    }
                ],
            }

    monkeypatch.setattr("shroodler.crawler.crawl_url", lambda *a, **k: FakeResult())
    state = ProgramState(slug="lab")
    result = execute_action(
        CrawlAction(urls=["http://127.0.0.1/api/a", "https://evil.example/x"]),
        state,
        _config(dry_run=False),
        pacer=Pacer(0),
    )
    assert result["pages_crawled"] >= 1
    assert result["new_endpoints"] >= 1
    assert "http://127.0.0.1/api/a" in state.endpoints


def test_execute_crawl_uses_headless_for_webgoat(monkeypatch):
    seen: dict = {}

    class FakeResult:
        def to_dict(self):
            return {
                "pages": [
                    {
                        "url": "http://127.0.0.1:8080/WebGoat/start.mvc",
                        "status_code": 200,
                    }
                ],
                "xhr_endpoints": [
                    {
                        "url": "http://127.0.0.1:8080/WebGoat/SqlInjection/attack2",
                        "method": "POST",
                        "params": [{"name": "username", "value": "guest", "in": "body"}],
                    }
                ],
                "findings": [],
            }

    def fake_crawl(url, **kwargs):
        seen["url"] = url
        seen["kwargs"] = kwargs
        return FakeResult()

    monkeypatch.setattr("shroodler.crawler.crawl_url", fake_crawl)
    state = ProgramState(slug="lab")
    execute_action(
        CrawlAction(urls=["http://127.0.0.1:8080/WebGoat/start.mvc"]),
        state,
        _config(
            dry_run=False,
            target="http://127.0.0.1:8080/WebGoat",
            login_recipe="/tmp/owner.json",
        ),
        pacer=Pacer(0),
    )
    assert seen["kwargs"]["mode"] == "headless"
    assert seen["kwargs"]["login_recipe"] == "/tmp/owner.json"
    attack = "http://127.0.0.1:8080/WebGoat/SqlInjection/attack2"
    assert attack in state.endpoints
    assert state.endpoints[attack]["method"] == "POST"
    assert state.endpoints[attack]["params"][0]["name"] == "username"


def test_execute_crawl_records_per_url_errors(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("network down")

    monkeypatch.setattr("shroodler.crawler.crawl_url", boom)
    state = ProgramState(slug="lab")
    result = execute_action(
        CrawlAction(urls=["http://127.0.0.1/"]),
        state,
        _config(dry_run=False),
        pacer=Pacer(0),
    )
    assert result["pages_crawled"] == 0
    assert result["errors"]


def test_execute_authz_merges_findings_and_marks_tested(monkeypatch):
    monkeypatch.setattr(
        "shroodler.agent.run_authz_diff",
        lambda urls, **kw: {
            "findings": [
                {
                    "id": "authz-still-accessible",
                    "severity": "medium",
                    "category": "auth",
                    "url": urls[0],
                    "description": "reachable",
                    "confidence": "confirmed",
                }
            ]
        },
    )
    state = ProgramState(
        slug="lab",
        endpoints={"http://127.0.0.1/api/a": _endpoint(last_seen=_now_iso())},
    )
    result = execute_action(
        AuthzDiffAction(urls=["http://127.0.0.1/api/a"]),
        state,
        _config(
            dry_run=False,
            higher_priv_jar="high.json",
            lower_priv_jar="low.json",
        ),
        pacer=Pacer(0),
    )
    assert result["findings_added"] == 1
    assert state.endpoints["http://127.0.0.1/api/a"]["tested_authz"] is True
    assert state.findings[0].confidence == "confirmed"


def test_execute_peer_write_marks_owning_endpoints(monkeypatch):
    monkeypatch.setattr(
        "shroodler.agent.run_peer_write",
        lambda object_ids, **kw: {
            "findings": [
                {
                    "id": "peer-write-idor",
                    "severity": "high",
                    "category": "auth",
                    "url": "http://127.0.0.1/api/users/1",
                    "description": "peer write",
                    "confidence": "confirmed",
                }
            ]
        },
    )
    state = ProgramState(
        slug="lab",
        endpoints={
            "http://127.0.0.1/api/users/1": _endpoint(
                last_seen=_now_iso(), tested_authz=True
            )
        },
        object_ids={"/api/users/{id}": ["1"]},
    )
    result = execute_action(
        PeerWriteAction(object_ids=["1"]),
        state,
        _config(dry_run=False, owner_cookie="a=1", peer_cookie="b=2"),
        pacer=Pacer(0),
    )
    assert result["findings_added"] == 1
    assert state.endpoints["http://127.0.0.1/api/users/1"]["tested_peer_write"] is True


def test_execute_report_summarizes_confirmed():
    state = ProgramState(
        slug="lab",
        findings=[
            Finding(
                id="authz-broken-access-control",
                severity="high",
                category="auth",
                url="http://127.0.0.1/x",
                description="ok",
                confidence="confirmed",
            )
        ],
    )
    result = execute_action(ReportAction(), state, _config(), pacer=Pacer(0))
    assert result["confirmed"] == 1
    assert result["summary"][0]["id"] == "authz-broken-access-control"


def test_confirmed_findings_skip_suppressed():
    from shroodler.engagement_history import record_suppression

    state = ProgramState(
        slug="lab",
        findings=[
            Finding(
                id="authz-broken-access-control",
                severity="high",
                category="auth",
                url="http://127.0.0.1/x",
                description="ok",
                confidence="confirmed",
            )
        ],
    )
    record_suppression(state, "authz-broken-access-control", "*", "accepted")
    assert _confirmed_findings(state) == []
    result = execute_action(ReportAction(), state, _config(), pacer=Pacer(0))
    assert result["confirmed"] == 0


def test_loop_stops_after_consecutive_errors(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    load("lab")

    def always_fail(action, state, config, pacer=None):
        raise RuntimeError("nope")

    monkeypatch.setattr(
        "shroodler.agent.decide_next_action",
        lambda state, config, *args, **kwargs: CrawlAction(urls=["http://127.0.0.1/"]),
    )
    monkeypatch.setattr("shroodler.agent.execute_action", always_fail)
    result = run_agent(
        _config(program="lab", target="http://127.0.0.1/", dry_run=False, max_iterations=2)
    )
    assert result.iterations == 2
    assert len(result.errors) == 2


def test_in_scope_target_is_allowed(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    state = load("lab")
    state.scope_urls = ["http://127.0.0.1/app"]
    save(state)
    result = run_agent(
        _config(
            program="lab",
            target="http://127.0.0.1/",
            dry_run=True,
            max_iterations=1,
        )
    )
    assert result.iterations == 1


def test_cmd_agent_dry_run_stdout(tmp_path, monkeypatch, capsys):
    import argparse
    import json

    from shroodler.cli import cmd_agent

    monkeypatch.setenv("HOME", str(tmp_path))
    load("lab")
    ns = argparse.Namespace(
        program="lab",
        target="http://127.0.0.1/",
        max_iterations=1,
        max_pages_per_crawl=5,
        login_recipe=None,
        higher_priv_jar=None,
        lower_priv_jar=None,
        owner_cookie=None,
        peer_cookie=None,
        dry_run=True,
    )
    assert cmd_agent(ns) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["iterations"] == 1
    assert "state_path" in payload
    assert payload["confirmed"] == 0


def test_cmd_agent_no_openapi_disables_both_flags(tmp_path, monkeypatch, capsys):
    import argparse

    from shroodler.cli import cmd_agent

    monkeypatch.setenv("HOME", str(tmp_path))
    load("lab")
    captured: list = []

    def fake_run(config):
        captured.append(config)
        from shroodler.agent import AgentResult

        return AgentResult(iterations=0, confirmed=0, log=[], state_path="")

    monkeypatch.setattr("shroodler.agent.run_agent", fake_run)
    ns = argparse.Namespace(
        program="lab",
        target="http://127.0.0.1/",
        max_iterations=1,
        max_pages_per_crawl=5,
        login_recipe=None,
        higher_priv_jar=None,
        lower_priv_jar=None,
        owner_cookie=None,
        peer_cookie=None,
        dry_run=True,
        no_openapi=True,
    )
    assert cmd_agent(ns) == 0
    assert captured[0].run_openapi_discovery is False
    assert captured[0].run_openapi_probes is False


def test_cmd_agent_no_probe_flags_disable_new_probes(tmp_path, monkeypatch, capsys):
    import argparse

    from shroodler.cli import cmd_agent

    monkeypatch.setenv("HOME", str(tmp_path))
    load("lab")
    captured: list = []

    def fake_run(config):
        captured.append(config)
        from shroodler.agent import AgentResult

        return AgentResult(iterations=0, confirmed=0, log=[], state_path="")

    monkeypatch.setattr("shroodler.agent.run_agent", fake_run)
    ns = argparse.Namespace(
        program="lab",
        target="http://127.0.0.1/",
        max_iterations=1,
        max_pages_per_crawl=5,
        login_recipe=None,
        higher_priv_jar=None,
        lower_priv_jar=None,
        owner_cookie=None,
        peer_cookie=None,
        dry_run=True,
        no_ssrf=True,
        no_open_redirect=True,
        no_host_header=True,
        no_ssti=True,
        no_xxe=True,
        no_graphql=True,
        no_auto_register=True,
    )
    assert cmd_agent(ns) == 0
    assert captured[0].run_ssrf is False
    assert captured[0].run_open_redirect is False
    assert captured[0].run_host_header is False
    assert captured[0].run_ssti is False
    assert captured[0].run_xxe is False
    assert captured[0].run_graphql is False
    assert captured[0].auto_register is False


def test_run_agent_stops_immediately_when_nothing_left(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    state = load("lab")
    state.endpoints = {
        "http://127.0.0.1/api/a": _endpoint(
            last_seen=_now_iso(), tested_authz=True, tested_peer=True
        )
    }
    save(state)
    result = run_agent(
        _config(program="lab", target="http://127.0.0.1/", dry_run=True, max_iterations=5)
    )
    assert result.iterations == 0


def test_run_agent_dry_run_report_stops_loop(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    state = load("lab")
    state.endpoints = {
        "http://127.0.0.1/api/a": _endpoint(
            last_seen=_now_iso(), tested_authz=True, tested_peer=True
        )
    }
    state.findings = [
        Finding(
            id="authz-broken-access-control",
            severity="high",
            category="auth",
            url="http://127.0.0.1/api/a",
            description="confirmed lead",
            confidence="confirmed",
        )
    ]
    save(state)
    result = run_agent(
        _config(program="lab", target="http://127.0.0.1/", dry_run=True, max_iterations=5)
    )
    assert result.iterations == 1
    assert result.log[0]["action"] == "ReportAction"
    assert result.log[0].get("report") is True


def test_dry_run_describes_authz_and_peer_write(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    state = load("lab")
    state.endpoints = {
        "http://127.0.0.1/api/users/1": _endpoint(last_seen=_now_iso(), tested_authz=False)
    }
    state.object_ids = {"/api/users/{id}": ["1"]}
    save(state)
    result = run_agent(
        _config(
            program="lab",
            target="http://127.0.0.1/",
            dry_run=True,
            max_iterations=1,
            higher_priv_jar="high.json",
            lower_priv_jar="low.json",
        )
    )
    assert result.log[0]["action"] == "AuthzDiffAction"
    assert result.log[0]["urls"] == ["http://127.0.0.1/api/users/1"]

    state.endpoints["http://127.0.0.1/api/users/1"]["tested_authz"] = True
    save(state)
    result = run_agent(
        _config(
            program="lab",
            target="http://127.0.0.1/",
            dry_run=True,
            max_iterations=1,
            owner_cookie="session=a",
            peer_cookie="session=b",
        )
    )
    assert result.log[0]["action"] == "PeerWriteAction"
    assert "1" in result.log[0]["object_ids"]


def test_crawl_falls_back_to_target_when_endpoints_are_off_origin():
    state = ProgramState(
        slug="lab",
        endpoints={"https://evil.example/x": _endpoint(last_seen="")},
    )
    action = decide_next_action(state, _config())
    assert isinstance(action, CrawlAction)
    assert action.urls == ["http://127.0.0.1/"]


def test_playbook_builds_get_writes_from_object_ids():
    from shroodler.agent import _playbook_from_object_ids

    state = ProgramState(
        slug="lab",
        endpoints={"http://127.0.0.1/api/users/1": _endpoint(last_seen=_now_iso())},
        object_ids={"/api/users/{id}": ["1"]},
        sessions=[{"path": "/no/such/file.json"}],
    )
    playbook = _playbook_from_object_ids(state, ["1"], "http://127.0.0.1/")
    assert playbook["target"] == "http://127.0.0.1/"
    assert playbook["writes"][0]["id_value"] == "1"
    assert playbook["writes"][0]["url"] == "http://127.0.0.1/api/users/1"


def test_agent_config_has_triage_and_discovery_flags():
    cfg = _config(llm_triage=True, run_discovery=True)
    assert cfg.llm_triage is True
    assert cfg.run_discovery is True
    assert _config().llm_triage is False
    assert _config().run_discovery is False


def test_run_discovery_logs_pre_loop(tmp_path, monkeypatch, capsys):
    from shroodler.discovery import DiscoveryResult

    monkeypatch.setenv("HOME", str(tmp_path))
    load("lab")
    called = {}

    def fake_discover(state, target, config):
        called["dry_run"] = config.dry_run
        called["target"] = target
        return DiscoveryResult(
            subdomains_found=["www.example.com"],
            subdomains_added_to_state=1,
            endpoints_found=["https://example.com/api"],
            elapsed_ms=12,
        )

    monkeypatch.setattr("shroodler.discovery.discover", fake_discover)
    result = run_agent(
        _config(
            program="lab",
            target="http://127.0.0.1/",
            dry_run=True,
            run_discovery=True,
            max_iterations=1,
        )
    )
    err = capsys.readouterr().err
    compact = err.replace(" ", "")
    assert '"pre_loop": "discovery"' in err or '"pre_loop":"discovery"' in compact
    assert called["dry_run"] is True
    assert called["target"] == "http://127.0.0.1/"
    assert result.iterations >= 1


def test_run_discovery_dry_run_does_not_write_state(tmp_path, monkeypatch):
    from shroodler.discovery import DiscoveryResult

    monkeypatch.setenv("HOME", str(tmp_path))
    load("lab")
    saves: list[str] = []

    def fake_discover(state, target, config):
        assert config.dry_run is True
        return DiscoveryResult(
            subdomains_found=["www.example.com"],
            subdomains_added_to_state=1,
            endpoints_found=[],
            elapsed_ms=1,
        )

    monkeypatch.setattr("shroodler.discovery.discover", fake_discover)
    monkeypatch.setattr("shroodler.agent.program.save", lambda state: saves.append(state.slug))
    run_agent(
        _config(
            program="lab",
            target="http://127.0.0.1/",
            dry_run=True,
            run_discovery=True,
            max_iterations=1,
        )
    )
    assert saves == []


def test_decide_skips_crawl_after_three_zero_page_crawls():
    state = ProgramState(
        slug="lab",
        endpoints={
            "http://127.0.0.1/api/a": _endpoint(last_seen=""),
        },
    )
    cfg = _config(higher_priv_jar="/tmp/higher.json", lower_priv_jar="/tmp/lower.json")
    still_crawl = decide_next_action(state, cfg, crawl_stall_count=2)
    assert isinstance(still_crawl, CrawlAction)
    action = decide_next_action(state, cfg, crawl_stall_count=3)
    assert isinstance(action, AuthzDiffAction)
    assert action.urls == ["http://127.0.0.1/api/a"]


def test_auth_header_for_diff_uses_authorization_override(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("jar must not be read when Authorization override is set")

    monkeypatch.setattr("shroodler.agent._cookie_header_from_jar", boom)
    cfg = _config(
        higher_priv_jar="/tmp/higher.json",
        lower_priv_jar="/tmp/lower.json",
        owner_cookie="Authorization: Bearer api-xxx",
        peer_cookie="Authorization: Bearer api-yyy",
    )
    assert _auth_header_for_diff(cfg, "higher") == "Authorization: Bearer api-xxx"
    assert _auth_header_for_diff(cfg, "lower") == "Authorization: Bearer api-yyy"


def test_auth_header_for_diff_falls_back_to_jar(monkeypatch):
    monkeypatch.setattr(
        "shroodler.agent._cookie_header_from_jar",
        lambda path, target: f"cookie-from:{path}",
    )
    cfg = _config(
        higher_priv_jar="/tmp/higher.json",
        lower_priv_jar="/tmp/lower.json",
        owner_cookie="session=owner",
        peer_cookie="session=peer",
    )
    assert _auth_header_for_diff(cfg, "higher") == "cookie-from:/tmp/higher.json"
    assert _auth_header_for_diff(cfg, "lower") == "cookie-from:/tmp/lower.json"


def test_decide_write_authz_after_authz_before_peer_write():
    state = ProgramState(
        slug="lab",
        endpoints={
            "http://127.0.0.1/api/users/1": _endpoint(
                last_seen=_now_iso(), tested_authz=True, tested_peer=False
            ),
        },
        object_ids={"/api/users/{id}": ["1"]},
    )
    action = decide_next_action(
        state,
        _config(
            owner_cookie="Authorization: Bearer owner",
            peer_cookie="Authorization: Bearer peer",
            write_authz_endpoints=[
                {"method": "POST", "url": "http://127.0.0.1/api/v2/tokens", "body": {"name": "x"}}
            ],
        ),
    )
    assert isinstance(action, WriteAuthzAction)
    assert action.endpoints[0]["url"] == "http://127.0.0.1/api/v2/tokens"


def test_execute_write_authz_merges_findings(monkeypatch):
    monkeypatch.setattr(
        "shroodler.agent.run_write_authz",
        lambda endpoints, **kw: {
            "findings": [
                {
                    "id": "write-authz-unrestricted",
                    "severity": "high",
                    "category": "auth",
                    "url": endpoints[0]["url"],
                    "description": "lower wrote",
                    "confidence": "confirmed",
                }
            ],
            "probes": [
                {
                    "method": "POST",
                    "url": endpoints[0]["url"],
                    "higher_status": 201,
                    "lower_status": 201,
                }
            ],
            "skipped": [],
        },
    )
    state = ProgramState(slug="lab")
    result = execute_action(
        WriteAuthzAction(
            endpoints=[
                {"method": "POST", "url": "http://127.0.0.1/api/v2/tokens", "body": {"name": "x"}}
            ]
        ),
        state,
        _config(
            dry_run=False,
            owner_cookie="Authorization: Bearer owner",
            peer_cookie="Authorization: Bearer peer",
        ),
        pacer=Pacer(0),
    )
    assert result["findings_added"] == 1
    assert state.findings[0].id == "write-authz-unrestricted"
    assert state.findings[0].confidence == "confirmed"


def test_run_write_authz_skips_placeholders_and_records_finding():
    from shroodler.agent import run_write_authz

    class FakeResp:
        def __init__(self, status):
            self.status_code = status

    class FakeClient:
        def __init__(self):
            self.calls = []

        def request(self, method, url, **kw):
            self.calls.append((method, url, kw.get("headers") or {}))
            headers = kw.get("headers") or {}
            if headers.get("Authorization") == "Bearer peer":
                return FakeResp(201)
            return FakeResp(201)

        def close(self):
            pass

    client = FakeClient()
    out = run_write_authz(
        [
            {
                "method": "POST",
                "url": "http://127.0.0.1/api/v2/tokens",
                "body": {"name": "shroodler-probe"},
            },
            {
                "method": "PATCH",
                "url": "http://127.0.0.1/api/v2/members/{member_id}",
                "body": [{"op": "replace", "path": "/role", "value": "reader"}],
            },
        ],
        higher_header="Authorization: Bearer owner",
        lower_header="Authorization: Bearer peer",
        target="http://127.0.0.1/",
        allow_external=False,
        client=client,
    )
    assert any(f["id"] == "write-authz-unrestricted" for f in out["findings"])
    assert any("{member_id}" in s for s in out["skipped"])
    assert all("{member_id}" not in url for _, url, _ in client.calls)
    assert len(client.calls) == 2


def test_agent_config_run_probes_defaults_off():
    cfg = _config()
    assert cfg.run_probes is False
    assert cfg.reprobe is False
    assert cfg.probe_sqli is True
    assert cfg.probe_xss is True
    assert cfg.probe_path_traversal is True
    assert cfg.probe_jwt is True
    assert cfg.probe_idor is True
    assert cfg.run_ssrf is True
    assert cfg.run_open_redirect is True
    assert cfg.run_host_header is True
    assert cfg.run_ssti is True
    assert cfg.run_xxe is True
    assert cfg.run_graphql is True
    assert cfg.auto_register is True
    assert cfg.run_diff is False
    assert cfg.run_business_logic is False
    assert cfg.chain_specs == []
    assert cfg.run_dom_xss is False
    assert cfg.run_crlf is True
    assert cfg.run_prototype_pollution is True
    assert cfg.run_content_discovery is False  # test helper
    assert cfg.run_tls_check is False  # test helper
    assert cfg.run_rate_limit is True
    assert cfg.run_mass_assignment is True
    assert cfg.run_smuggling is False
    assert cfg.run_websocket is True


def test_agent_config_tls_and_content_discovery_default_on():
    cfg = AgentConfig(program="lab", target="http://127.0.0.1/")
    assert cfg.run_tls_check is True
    assert cfg.run_content_discovery is True
    assert cfg.run_dom_xss is False
    assert cfg.run_smuggling is False


def test_agent_config_openapi_defaults_on():
    cfg = AgentConfig(program="lab", target="http://127.0.0.1/")
    assert cfg.run_openapi_discovery is True
    assert cfg.run_openapi_probes is True


def test_authz_broken_access_control_is_not_tool_noise():
    assert "authz-broken-access-control" not in _TOOL_NOISE_IDS


def test_decide_probe_when_run_probes_and_queue_empty():
    state = ProgramState(
        slug="lab",
        endpoints={
            "http://127.0.0.1/search?q=1": _endpoint(
                last_seen=_now_iso(), tested_authz=True, tested_peer=True
            ),
        },
    )
    action = decide_next_action(state, _config(run_probes=True))
    assert isinstance(action, ProbeAction)
    assert action.urls == ["http://127.0.0.1/search?q=1"]


def test_decide_skips_probe_when_run_probes_false():
    state = ProgramState(
        slug="lab",
        endpoints={
            "http://127.0.0.1/search?q=1": _endpoint(
                last_seen=_now_iso(), tested_authz=True, tested_peer=True
            ),
        },
    )
    assert decide_next_action(state, _config()) is None


def test_decide_probe_before_report():
    state = ProgramState(
        slug="lab",
        endpoints={
            "http://127.0.0.1/search?q=1": _endpoint(
                last_seen=_now_iso(), tested_authz=True, tested_peer=True
            ),
        },
        findings=[
            Finding(
                id="authz-broken-access-control",
                severity="high",
                category="auth",
                url="http://127.0.0.1/search?q=1",
                description="confirmed lead",
                confidence="confirmed",
            )
        ],
    )
    action = decide_next_action(state, _config(run_probes=True))
    assert isinstance(action, ProbeAction)


def test_decide_skips_already_tested_payload():
    state = ProgramState(
        slug="lab",
        endpoints={
            "http://127.0.0.1/search?q=1": {
                **_endpoint(last_seen=_now_iso(), tested_authz=True, tested_peer=True),
                "tested_payload": True,
            },
        },
        findings=[
            Finding(
                id="sqli",
                severity="critical",
                category="payload",
                url="http://127.0.0.1/search?q=1",
                description="sqli",
                confidence="confirmed",
            )
        ],
    )
    action = decide_next_action(state, _config(run_probes=True))
    assert isinstance(action, ReportAction)


def test_execute_probe_merges_findings_and_marks_tested(monkeypatch):
    from shroodler.models import Finding as F

    monkeypatch.setattr(
        "shroodler.probes.sqli.probe_sqli",
        lambda url, method, params, cookie, **kw: [
            F(
                id="sqli",
                severity="critical",
                category="payload",
                url=url,
                description="error-based",
                confidence="confirmed",
            )
        ],
    )
    monkeypatch.setattr("shroodler.probes.xss.probe_xss", lambda *a, **k: [])
    monkeypatch.setattr(
        "shroodler.probes.path_traversal.probe_path_traversal", lambda *a, **k: []
    )
    monkeypatch.setattr("shroodler.probes.jwt.probe_jwt", lambda *a, **k: [])
    monkeypatch.setattr("shroodler.probes.idor.probe_idor", lambda *a, **k: [])
    monkeypatch.setattr("shroodler.probes.ssrf.probe_ssrf", lambda *a, **k: [])
    monkeypatch.setattr(
        "shroodler.probes.open_redirect.probe_open_redirect", lambda *a, **k: []
    )
    monkeypatch.setattr(
        "shroodler.probes.host_header.probe_host_header", lambda *a, **k: []
    )
    monkeypatch.setattr("shroodler.probes.ssti.probe_ssti", lambda *a, **k: [])
    monkeypatch.setattr("shroodler.probes.xxe.probe_xxe", lambda *a, **k: [])
    monkeypatch.setattr("shroodler.probes.graphql.probe_graphql", lambda *a, **k: [])

    url = "http://127.0.0.1/search?q=1"
    state = ProgramState(
        slug="lab",
        endpoints={
            url: {
                **_endpoint(last_seen=_now_iso()),
                "method": "GET",
                "params": [{"name": "q"}],
            }
        },
    )
    result = execute_action(
        ProbeAction(urls=[url]),
        state,
        _config(dry_run=False, owner_cookie="session=owner", peer_cookie="session=peer"),
        pacer=Pacer(0),
    )
    assert result["findings_added"] == 1
    assert state.findings[0].id == "sqli"
    assert state.endpoints[url]["tested_payload"] is True


def test_execute_probe_records_per_probe_errors(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("probe exploded")

    monkeypatch.setattr("shroodler.probes.sqli.probe_sqli", boom)
    monkeypatch.setattr("shroodler.probes.xss.probe_xss", lambda *a, **k: [])
    monkeypatch.setattr(
        "shroodler.probes.path_traversal.probe_path_traversal", lambda *a, **k: []
    )
    monkeypatch.setattr("shroodler.probes.jwt.probe_jwt", lambda *a, **k: [])
    monkeypatch.setattr("shroodler.probes.idor.probe_idor", lambda *a, **k: [])
    monkeypatch.setattr("shroodler.probes.ssrf.probe_ssrf", lambda *a, **k: [])
    monkeypatch.setattr(
        "shroodler.probes.open_redirect.probe_open_redirect", lambda *a, **k: []
    )
    monkeypatch.setattr(
        "shroodler.probes.host_header.probe_host_header", lambda *a, **k: []
    )
    monkeypatch.setattr("shroodler.probes.ssti.probe_ssti", lambda *a, **k: [])
    monkeypatch.setattr("shroodler.probes.xxe.probe_xxe", lambda *a, **k: [])
    monkeypatch.setattr("shroodler.probes.graphql.probe_graphql", lambda *a, **k: [])

    url = "http://127.0.0.1/search?q=1"
    state = ProgramState(
        slug="lab",
        endpoints={
            url: {
                **_endpoint(last_seen=_now_iso()),
                "method": "GET",
                "params": [{"name": "q"}],
            }
        },
    )
    result = execute_action(
        ProbeAction(urls=[url]),
        state,
        _config(dry_run=False),
        pacer=Pacer(0),
    )
    assert result["findings_added"] == 0
    assert result["errors"]
    assert state.endpoints[url]["tested_payload"] is True


def test_dry_run_describes_probe_action(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    state = load("lab")
    state.endpoints = {
        "http://127.0.0.1/search?q=1": _endpoint(
            last_seen=_now_iso(), tested_authz=True, tested_peer=True
        )
    }
    save(state)
    result = run_agent(
        _config(
            program="lab",
            target="http://127.0.0.1/",
            dry_run=True,
            run_probes=True,
            max_iterations=1,
        )
    )
    assert result.log[0]["action"] == "ProbeAction"
    assert result.log[0]["urls"] == ["http://127.0.0.1/search?q=1"]
    assert result.log[0]["dry_run"] is True


def test_reprobe_resets_tested_payload_before_loop(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    url = "http://127.0.0.1/search?q=1"
    state = load("lab")
    state.endpoints = {
        url: {
            **_endpoint(last_seen=_now_iso(), tested_authz=True, tested_peer=True),
            "tested_payload": True,
            "params": [{"name": "q"}],
        }
    }
    save(state)
    result = run_agent(
        _config(
            program="lab",
            target="http://127.0.0.1/",
            dry_run=True,
            run_probes=True,
            reprobe=True,
            max_iterations=1,
        )
    )
    assert result.log[0]["action"] == "ProbeAction"
    assert result.log[0]["urls"] == [url]
    reloaded = load("lab")
    assert reloaded.endpoints[url]["tested_payload"] is False


def test_untested_probe_requeues_when_last_seen_newer_than_tested_at():
    url = "http://127.0.0.1/search"
    state = ProgramState(
        slug="lab",
        endpoints={
            url: {
                **_endpoint(
                    last_seen="2026-09-09T12:00:00Z",
                    tested_authz=True,
                    tested_peer=True,
                ),
                "tested_payload": True,
                "tested_payload_at": "2026-09-08T12:00:00Z",
                "params": [{"name": "q"}],
            }
        },
    )
    assert _untested_probe_urls(state, _config(run_probes=True)) == [url]


def test_backfill_confirms_existing_authz_findings(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    state = load("lab")
    state.endpoints = {
        "http://127.0.0.1/IDOR/profile": _endpoint(
            last_seen=_now_iso(), tested_authz=True, tested_peer=True
        )
    }
    state.findings = [
        Finding(
            id="authz-broken-access-control",
            severity="high",
            category="auth",
            url="http://127.0.0.1/IDOR/profile",
            description="reachable",
        )
    ]
    save(state)
    result = run_agent(
        _config(
            program="lab",
            target="http://127.0.0.1/",
            dry_run=True,
            max_iterations=1,
        )
    )
    assert result.confirmed >= 1
    reloaded = load("lab")
    assert reloaded.findings[0].confidence == "confirmed"


def test_decide_openapi_discover_after_crawl_before_authz():
    state = ProgramState(
        slug="lab",
        endpoints={
            "http://127.0.0.1/api/a": _endpoint(last_seen=_now_iso(), tested_authz=False),
        },
    )
    action = decide_next_action(
        state,
        _config(
            run_openapi_discovery=True,
            higher_priv_jar="/tmp/higher.json",
            lower_priv_jar="/tmp/lower.json",
        ),
    )
    assert isinstance(action, OpenApiDiscoverAction)


def test_decide_skips_openapi_discover_when_spec_url_set():
    state = ProgramState(
        slug="lab",
        endpoints={
            "http://127.0.0.1/api/a": _endpoint(
                last_seen=_now_iso(), tested_authz=True, tested_peer=True
            ),
        },
        openapi_spec_url="http://127.0.0.1/openapi.json",
    )
    action = decide_next_action(state, _config(run_openapi_discovery=True))
    assert action is None


def test_decide_openapi_discover_even_when_run_probes_false():
    state = ProgramState(
        slug="lab",
        endpoints={
            "http://127.0.0.1/api/a": _endpoint(
                last_seen=_now_iso(), tested_authz=True, tested_peer=True
            ),
        },
    )
    action = decide_next_action(
        state, _config(run_openapi_discovery=True, run_probes=False)
    )
    assert isinstance(action, OpenApiDiscoverAction)


def test_decide_openapi_probe_after_probe_when_untested_spec():
    spec_url = "http://127.0.0.1/api/account/{accountId}"
    state = ProgramState(
        slug="lab",
        endpoints={
            "http://127.0.0.1/search?q=1": {
                **_endpoint(last_seen=_now_iso(), tested_authz=True, tested_peer=True),
                "tested_payload": True,
            },
            spec_url: _endpoint(last_seen=_now_iso(), tested_authz=True, tested_peer=True),
        },
        openapi_spec_url="http://127.0.0.1/openapi.json",
        openapi_endpoints=[
            {
                "url": spec_url,
                "method": "GET",
                "params": [
                    {"name": "accountId", "in": "path", "type": "integer", "example": 800002}
                ],
                "auth_required": True,
            }
        ],
    )
    action = decide_next_action(
        state, _config(run_probes=True, run_openapi_probes=True)
    )
    assert isinstance(action, OpenApiProbeAction)
    assert action.endpoints[0]["url"] == spec_url


def test_decide_openapi_probe_without_run_probes():
    spec_url = "http://127.0.0.1/api/account/{accountId}"
    state = ProgramState(
        slug="lab",
        endpoints={
            spec_url: _endpoint(
                last_seen=_now_iso(), tested_authz=True, tested_peer=True
            ),
        },
        openapi_spec_url="http://127.0.0.1/openapi.json",
        openapi_endpoints=[
            {"url": spec_url, "method": "GET", "params": [], "auth_required": False}
        ],
    )
    action = decide_next_action(
        state, _config(run_probes=False, run_openapi_probes=True)
    )
    assert isinstance(action, OpenApiProbeAction)


def test_decide_skips_openapi_probe_when_disabled():
    spec_url = "http://127.0.0.1/api/x"
    state = ProgramState(
        slug="lab",
        endpoints={
            spec_url: _endpoint(
                last_seen=_now_iso(), tested_authz=True, tested_peer=True
            ),
        },
        openapi_spec_url="http://127.0.0.1/openapi.json",
        openapi_endpoints=[{"url": spec_url, "method": "GET", "params": []}],
    )
    assert decide_next_action(state, _config(run_openapi_probes=False)) is None


def test_execute_openapi_discover_merges(monkeypatch):
    from shroodler.openapi import OpenApiEndpoint
    from shroodler.pacer import Pacer

    monkeypatch.setattr(
        "shroodler.openapi.discover_specs",
        lambda *a, **k: [("http://127.0.0.1/openapi.json", {"openapi": "3.0.0"})],
    )
    monkeypatch.setattr(
        "shroodler.openapi.parse_spec",
        lambda spec, base: [
            OpenApiEndpoint(
                url="http://127.0.0.1/users",
                method="GET",
                params=[{"name": "q", "in": "query", "type": "string"}],
                auth_required=False,
            )
        ],
    )
    state = ProgramState(
        slug="lab",
        endpoints={
            "http://127.0.0.1/": _endpoint(last_seen=_now_iso()),
        },
    )
    result = execute_action(
        OpenApiDiscoverAction(),
        state,
        _config(dry_run=False, run_openapi_discovery=True),
        pacer=Pacer(0),
    )
    assert result["new_endpoints"] >= 1
    assert state.openapi_spec_url == "http://127.0.0.1/openapi.json"
    assert state.endpoints["http://127.0.0.1/users"]["source"] == "openapi"
    assert any(f.id == "openapi-spec-found" for f in state.findings)


def test_execute_openapi_probe_marks_tested(monkeypatch):
    from shroodler.models import Finding as F
    from shroodler.pacer import Pacer

    monkeypatch.setattr(
        "shroodler.probes.openapi_probe.probe_openapi_endpoints",
        lambda endpoints, **kw: [
            F(
                id="openapi-unauthenticated",
                severity="high",
                category="auth",
                url="http://127.0.0.1/api/secret",
                description="open",
                confidence="confirmed",
            )
        ],
    )
    url = "http://127.0.0.1/api/secret"
    row = {"url": url, "method": "GET", "params": [], "auth_required": True}
    state = ProgramState(
        slug="lab",
        endpoints={url: _endpoint(last_seen=_now_iso())},
        openapi_spec_url="http://127.0.0.1/openapi.json",
        openapi_endpoints=[row],
    )
    result = execute_action(
        OpenApiProbeAction(endpoints=[row]),
        state,
        _config(dry_run=False, run_openapi_probes=True),
        pacer=Pacer(0),
    )
    assert result["findings_added"] == 1
    assert state.findings[0].id == "openapi-unauthenticated"
    assert state.endpoints[url]["tested_payload"] is True
    assert row["tested_payload"] is True


def test_dry_run_describes_openapi_discover(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    state = load("lab")
    state.endpoints = {
        "http://127.0.0.1/api/a": _endpoint(
            last_seen=_now_iso(), tested_authz=True, tested_peer=True
        )
    }
    save(state)
    result = run_agent(
        _config(
            program="lab",
            target="http://127.0.0.1/",
            dry_run=True,
            run_openapi_discovery=True,
            max_iterations=1,
        )
    )
    assert result.log[0]["action"] == "OpenApiDiscoverAction"
    assert result.log[0].get("openapi_discover") is True
    assert result.log[0]["dry_run"] is True


def test_decide_auto_register_before_authz():
    state = ProgramState(
        slug="lab",
        endpoints={
            "http://127.0.0.1/api/a": _endpoint(last_seen=_now_iso(), tested_authz=False),
            "http://127.0.0.1/register": {
                **_endpoint(last_seen=_now_iso(), tested_authz=False),
                "method": "POST",
            },
        },
    )
    action = decide_next_action(
        state,
        _config(higher_priv_jar="/tmp/higher.json", owner_cookie="session=owner"),
    )
    assert isinstance(action, AutoRegisterAction)


def test_decide_skips_auto_register_when_peer_exists():
    state = ProgramState(
        slug="lab",
        endpoints={
            "http://127.0.0.1/api/a": _endpoint(last_seen=_now_iso(), tested_authz=False),
            "http://127.0.0.1/register": {
                **_endpoint(last_seen=_now_iso()),
                "method": "POST",
            },
        },
    )
    action = decide_next_action(
        state,
        _config(
            higher_priv_jar="/tmp/higher.json",
            lower_priv_jar="/tmp/lower.json",
            owner_cookie="session=owner",
        ),
    )
    assert isinstance(action, AuthzDiffAction)


def test_decide_skips_auto_register_when_disabled():
    state = ProgramState(
        slug="lab",
        endpoints={
            "http://127.0.0.1/api/a": _endpoint(
                last_seen=_now_iso(), tested_authz=True, tested_peer=True
            ),
            "http://127.0.0.1/register": {
                **_endpoint(last_seen=_now_iso(), tested_authz=True, tested_peer=True),
                "method": "POST",
            },
        },
    )
    action = decide_next_action(
        state,
        _config(auto_register=False, owner_cookie="session=owner"),
    )
    assert not isinstance(action, AutoRegisterAction)


def test_execute_auto_register_sets_peer_cookie(monkeypatch):
    from shroodler.models import Finding as F

    def fake_register(state, config, **kw):
        config.peer_cookie = "session=peer"
        state.peer_session = {"name": "session", "value": "peer"}
        return [
            F(
                id="peer-account-registered",
                severity="info",
                category="scan-note",
                url="http://127.0.0.1/register",
                description="registered",
                confidence="confirmed",
            )
        ]

    monkeypatch.setattr("shroodler.second_account.auto_register_peer", fake_register)
    state = ProgramState(slug="lab")
    config = _config(dry_run=False, owner_cookie="session=owner")
    result = execute_action(AutoRegisterAction(), state, config, pacer=Pacer(0))
    assert result["findings_added"] == 1
    assert config.peer_cookie == "session=peer"
    assert state.findings[0].id == "peer-account-registered"


def test_execute_probe_runs_ssrf_and_host_header(monkeypatch):
    called: list[str] = []

    def mark(name):
        def _fn(*a, **k):
            called.append(name)
            return []

        return _fn

    monkeypatch.setattr("shroodler.probes.sqli.probe_sqli", mark("sqli"))
    monkeypatch.setattr("shroodler.probes.xss.probe_xss", mark("xss"))
    monkeypatch.setattr(
        "shroodler.probes.path_traversal.probe_path_traversal", mark("path")
    )
    monkeypatch.setattr("shroodler.probes.jwt.probe_jwt", mark("jwt"))
    monkeypatch.setattr("shroodler.probes.idor.probe_idor", mark("idor"))
    monkeypatch.setattr("shroodler.probes.ssrf.probe_ssrf", mark("ssrf"))
    monkeypatch.setattr(
        "shroodler.probes.open_redirect.probe_open_redirect", mark("open-redirect")
    )
    monkeypatch.setattr(
        "shroodler.probes.host_header.probe_host_header", mark("host-header")
    )
    monkeypatch.setattr("shroodler.probes.ssti.probe_ssti", mark("ssti"))
    monkeypatch.setattr("shroodler.probes.xxe.probe_xxe", mark("xxe"))
    monkeypatch.setattr("shroodler.probes.graphql.probe_graphql", mark("graphql"))
    monkeypatch.setattr("shroodler.probes.crlf.probe_crlf", mark("crlf"))
    monkeypatch.setattr(
        "shroodler.probes.prototype_pollution.probe_prototype_pollution",
        mark("pp"),
    )
    monkeypatch.setattr("shroodler.probes.dom_xss.probe_dom_xss", mark("dom-xss"))
    monkeypatch.setattr("shroodler.probes.rate_limit.probe_rate_limit", mark("rl"))
    monkeypatch.setattr(
        "shroodler.probes.mass_assignment.probe_mass_assignment", mark("ma")
    )
    monkeypatch.setattr("shroodler.probes.smuggling.probe_smuggling", mark("smuggle"))
    monkeypatch.setattr(
        "shroodler.probes.websocket.probe_websocket", lambda *a, **k: ([], [])
    )

    url_a = "http://127.0.0.1/fetch?url=1"
    url_b = "http://127.0.0.1/other?url=2"
    state = ProgramState(
        slug="lab",
        endpoints={
            url_a: {
                **_endpoint(last_seen=_now_iso()),
                "method": "GET",
                "params": [{"name": "url"}],
            },
            url_b: {
                **_endpoint(last_seen=_now_iso()),
                "method": "GET",
                "params": [{"name": "url"}],
            },
        },
    )
    execute_action(
        ProbeAction(urls=[url_a, url_b]),
        state,
        _config(dry_run=False, owner_cookie="session=owner"),
        pacer=Pacer(0),
    )
    assert called.count("ssrf") == 2
    assert called.count("open-redirect") == 2
    assert called.count("host-header") == 1
    assert called.count("ssti") == 2
    assert called.count("xxe") == 2
    assert called.count("graphql") == 1


def test_execute_probe_honors_no_ssrf_flags(monkeypatch):
    called: list[str] = []

    def mark(name):
        def _fn(*a, **k):
            called.append(name)
            return []

        return _fn

    monkeypatch.setattr("shroodler.probes.sqli.probe_sqli", mark("sqli"))
    monkeypatch.setattr("shroodler.probes.xss.probe_xss", mark("xss"))
    monkeypatch.setattr(
        "shroodler.probes.path_traversal.probe_path_traversal", mark("path")
    )
    monkeypatch.setattr("shroodler.probes.jwt.probe_jwt", lambda *a, **k: [])
    monkeypatch.setattr("shroodler.probes.idor.probe_idor", lambda *a, **k: [])
    monkeypatch.setattr("shroodler.probes.ssrf.probe_ssrf", mark("ssrf"))
    monkeypatch.setattr(
        "shroodler.probes.open_redirect.probe_open_redirect", mark("open-redirect")
    )
    monkeypatch.setattr(
        "shroodler.probes.host_header.probe_host_header", mark("host-header")
    )
    monkeypatch.setattr("shroodler.probes.ssti.probe_ssti", mark("ssti"))
    monkeypatch.setattr("shroodler.probes.xxe.probe_xxe", mark("xxe"))
    monkeypatch.setattr("shroodler.probes.graphql.probe_graphql", mark("graphql"))
    monkeypatch.setattr("shroodler.probes.crlf.probe_crlf", mark("crlf"))
    monkeypatch.setattr(
        "shroodler.probes.prototype_pollution.probe_prototype_pollution",
        mark("pp"),
    )
    monkeypatch.setattr("shroodler.probes.dom_xss.probe_dom_xss", mark("dom-xss"))
    monkeypatch.setattr("shroodler.probes.rate_limit.probe_rate_limit", mark("rl"))
    monkeypatch.setattr(
        "shroodler.probes.mass_assignment.probe_mass_assignment", mark("ma")
    )
    monkeypatch.setattr("shroodler.probes.smuggling.probe_smuggling", mark("smuggle"))
    monkeypatch.setattr(
        "shroodler.probes.websocket.probe_websocket", lambda *a, **k: ([], [])
    )

    url = "http://127.0.0.1/fetch?url=1"
    state = ProgramState(
        slug="lab",
        endpoints={
            url: {
                **_endpoint(last_seen=_now_iso()),
                "method": "GET",
                "params": [{"name": "url"}],
            }
        },
    )
    execute_action(
        ProbeAction(urls=[url]),
        state,
        _config(
            dry_run=False,
            run_ssrf=False,
            run_open_redirect=False,
            run_host_header=False,
            run_ssti=False,
            run_xxe=False,
            run_graphql=False,
        ),
        pacer=Pacer(0),
    )
    assert "ssrf" not in called
    assert "open-redirect" not in called
    assert "host-header" not in called
    assert "ssti" not in called
    assert "xxe" not in called
    assert "graphql" not in called


def test_decide_tls_check_before_crawl_for_https():
    state = ProgramState(slug="lab")
    action = decide_next_action(
        state, _config(target="https://example.com/", run_tls_check=True)
    )
    assert isinstance(action, TLSCheckAction)


def test_decide_content_discover_before_probe():
    state = ProgramState(
        slug="lab",
        endpoints={
            "http://127.0.0.1/api/a": _endpoint(
                last_seen=_now_iso(), tested_authz=True, tested_peer=True
            )
        },
    )
    action = decide_next_action(
        state, _config(run_content_discovery=True, run_probes=True)
    )
    assert isinstance(action, ContentDiscoverAction)


def test_decide_peer_write_still_before_probe():
    state = ProgramState(
        slug="lab",
        endpoints={
            "http://127.0.0.1/api/users/1": _endpoint(
                last_seen=_now_iso(), tested_authz=True, tested_peer=False
            )
        },
        object_ids={"/api/users/{id}": ["1"]},
    )
    action = decide_next_action(
        state,
        _config(
            owner_cookie="session=owner",
            peer_cookie="session=peer",
            run_probes=True,
        ),
    )
    assert isinstance(action, PeerWriteAction)


def test_untested_probe_urls_skip_out_of_scope(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    from shroodler.scope import save_scope

    save_scope(
        "lab",
        {"include": ["example.com"], "exclude": [], "allow_subdomains": True},
    )
    state = ProgramState(
        slug="lab",
        endpoints={
            "http://127.0.0.1/api/a": {
                **_endpoint(last_seen=_now_iso()),
                "params": [{"name": "q"}],
            }
        },
    )
    assert _untested_probe_urls(state, _config(run_probes=True)) == []
    err = capsys.readouterr().err
    assert "scope-excluded" in err


def test_execute_report_deduplicates_findings():
    state = ProgramState(
        slug="lab",
        findings=[
            Finding(
                id="xss-reflected",
                severity="high",
                category="payload",
                url="http://127.0.0.1/x",
                description="a",
                evidence="param=q",
                confidence="heuristic",
            ),
            Finding(
                id="xss-reflected",
                severity="high",
                category="payload",
                url="http://127.0.0.1/x",
                description="b",
                evidence="param=q",
                confidence="confirmed",
            ),
        ],
    )
    result = execute_action(ReportAction(), state, _config())
    assert len(state.findings) == 1
    assert state.findings[0].confidence == "confirmed"
    assert result["confirmed"] == 1


def test_agent_config_llm_agent_defaults_off():
    cfg = _config()
    assert cfg.llm_agent is False
    assert cfg.llm_agent_model == "claude-sonnet-5"
    assert cfg.llm_agent_max_cost_usd == 5.0


def test_default_loop_does_not_call_planner(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    load("lab")

    def boom(*_a, **_k):
        raise AssertionError("planner must not run when llm_agent is False")

    monkeypatch.setattr("shroodler.llm_agent.planner.plan_next_action", boom)
    result = run_agent(
        _config(
            program="lab",
            target="http://127.0.0.1/",
            dry_run=True,
            max_iterations=1,
            llm_agent=False,
        )
    )
    assert result.iterations == 1
    assert result.log[0]["action"] == "CrawlAction"


def test_llm_agent_uses_planner_and_logs_reasoning(tmp_path, monkeypatch, capsys):
    from shroodler.llm_agent.planner import PlannerDecision

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    load("lab")

    def fake_plan(*_a, **_k):
        return PlannerDecision(
            action="hypothesise",
            params={"hypothesis": "try xss", "target_url": "http://127.0.0.1/", "reasoning": "x"},
            reasoning="check search next",
        )

    monkeypatch.setattr("shroodler.llm_agent.planner.plan_next_action", fake_plan)
    result = run_agent(
        _config(
            program="lab",
            target="http://127.0.0.1/",
            dry_run=True,
            max_iterations=1,
            llm_agent=True,
            run_tls_check=False,
            run_content_discovery=False,
        )
    )
    assert result.iterations == 1
    assert result.log[0]["action"] == "hypothesise"
    assert result.log[0]["reasoning"] == "check search next"
    assert result.log[0]["findings_added"] == 0


def test_llm_agent_falls_back_to_decide_next_action(tmp_path, monkeypatch):
    from shroodler.llm_agent.planner import PlannerDecision

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    load("lab")

    def fake_plan(*_a, **_k):
        return PlannerDecision(action=None, fallback=True, fallback_reason="invalid JSON")

    monkeypatch.setattr("shroodler.llm_agent.planner.plan_next_action", fake_plan)
    result = run_agent(
        _config(
            program="lab",
            target="http://127.0.0.1/",
            dry_run=True,
            max_iterations=1,
            llm_agent=True,
            run_tls_check=False,
            run_content_discovery=False,
        )
    )
    assert result.log[0]["action"] == "CrawlAction"
    assert "reasoning" in result.log[0]


def test_llm_agent_cost_cap_emits_finding_and_stops(tmp_path, monkeypatch):
    from shroodler.llm_agent.planner import PlannerDecision

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    load("lab")

    def fake_plan(*_a, **_k):
        d = PlannerDecision(
            action="crawl",
            params={"url": "http://127.0.0.1/"},
            reasoning="explore",
            input_tokens=2_000_000,
            output_tokens=0,
            model="claude-sonnet-5",
        )
        return d

    monkeypatch.setattr("shroodler.llm_agent.planner.plan_next_action", fake_plan)
    result = run_agent(
        _config(
            program="lab",
            target="http://127.0.0.1/",
            dry_run=False,
            max_iterations=3,
            llm_agent=True,
            llm_agent_max_cost_usd=5.0,
            run_tls_check=False,
            run_content_discovery=False,
            run_openapi_discovery=False,
            run_openapi_probes=False,
        )
    )
    assert any(e.get("action") == "llm-cost-cap-reached" for e in result.log)
    state = load("lab")
    assert any(f.id == "llm-cost-cap-reached" for f in state.findings)
    assert any(f.category == "scan-note" for f in state.findings if f.id == "llm-cost-cap-reached")


def test_cmd_agent_llm_agent_requires_api_key(tmp_path, monkeypatch, capsys):
    import argparse

    from shroodler.cli import cmd_agent

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    called = {"n": 0}

    def boom(*_a, **_k):
        called["n"] += 1
        raise AssertionError("run_agent must not start")

    monkeypatch.setattr("shroodler.agent.run_agent", boom)
    ns = argparse.Namespace(
        program="lab",
        target="http://127.0.0.1/",
        llm_agent=True,
    )
    assert cmd_agent(ns) == 2
    assert called["n"] == 0
    err = capsys.readouterr().err
    assert "ANTHROPIC_API_KEY" in err


def test_agent_config_js_analysis_default_on():
    cfg = AgentConfig(program="lab", target="http://127.0.0.1/")
    assert cfg.run_js_analysis is True


def test_decide_js_analysis_after_crawl():
    from shroodler.agent import JSAnalysisAction

    state = ProgramState(
        slug="lab",
        endpoints={
            "http://127.0.0.1/": _endpoint(last_seen=_now_iso(), tested_authz=True, tested_peer=True)
        },
        js_urls=["http://127.0.0.1/static/app.js"],
    )
    action = decide_next_action(state, _config(run_js_analysis=True))
    assert isinstance(action, JSAnalysisAction)
    assert "http://127.0.0.1/static/app.js" in action.urls


def test_decide_skips_js_analysis_when_disabled():
    from shroodler.agent import JSAnalysisAction

    state = ProgramState(
        slug="lab",
        endpoints={
            "http://127.0.0.1/": _endpoint(last_seen=_now_iso(), tested_authz=True, tested_peer=True)
        },
        js_urls=["http://127.0.0.1/static/app.js"],
    )
    action = decide_next_action(state, _config(run_js_analysis=False))
    assert not isinstance(action, JSAnalysisAction)


def test_execute_js_analysis_fetches_and_merges(monkeypatch):
    from shroodler.agent import JSAnalysisAction

    class FakeResp:
        status_code = 200
        text = 'fetch("/api/from-bundle"); const apiKey = "sk_live_abcdefghijklmnop";'
        content = text.encode()

    monkeypatch.setattr("shroodler.probes.common.request", lambda *a, **k: FakeResp())
    state = ProgramState(slug="lab", js_urls=["http://127.0.0.1/app.js"])
    result = execute_action(
        JSAnalysisAction(urls=["http://127.0.0.1/app.js"]),
        state,
        _config(dry_run=False, run_js_analysis=True),
        pacer=Pacer(0),
    )
    assert result["js_files"] == 1
    assert result["api_endpoints"] >= 1
    assert result["secrets"] >= 1
    ids = {f.id for f in state.findings}
    assert "js-api-endpoint-found" in ids
    assert "js-hardcoded-secret" in ids
    assert "js-analysis-complete" in ids
    secret_ev = next(f.evidence for f in state.findings if f.id == "js-hardcoded-secret")
    assert "sk_live_abcdefghijklmnop" not in (secret_ev or "")


def test_cmd_agent_no_js_analysis_disables_flag(tmp_path, monkeypatch, capsys):
    import argparse

    from shroodler.cli import cmd_agent

    monkeypatch.setenv("HOME", str(tmp_path))
    captured: list = []

    def fake_run(config):
        captured.append(config)
        from shroodler.agent import AgentResult

        return AgentResult(iterations=0, confirmed=0, log=[], state_path="")

    monkeypatch.setattr("shroodler.agent.run_agent", fake_run)
    ns = argparse.Namespace(
        program="lab",
        target="http://127.0.0.1/",
        max_iterations=1,
        max_pages_per_crawl=5,
        login_recipe=None,
        higher_priv_jar=None,
        lower_priv_jar=None,
        owner_cookie=None,
        peer_cookie=None,
        dry_run=True,
        no_js_analysis=True,
    )
    assert cmd_agent(ns) == 0
    assert captured[0].run_js_analysis is False


