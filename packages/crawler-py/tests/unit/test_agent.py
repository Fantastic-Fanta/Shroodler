from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from shroodler.agent import (
    AgentConfig,
    AuthzDiffAction,
    CrawlAction,
    PeerWriteAction,
    ReportAction,
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
        lambda state, config: CrawlAction(urls=["http://127.0.0.1/"]),
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
        lambda state, config: CrawlAction(urls=["http://127.0.0.1/"]),
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
    assert len(saves) == 4


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
        lambda state, config: CrawlAction(urls=["http://127.0.0.1/"]),
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


def test_loop_stops_after_consecutive_errors(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    load("lab")

    def always_fail(action, state, config, pacer=None):
        raise RuntimeError("nope")

    monkeypatch.setattr(
        "shroodler.agent.decide_next_action",
        lambda state, config: CrawlAction(urls=["http://127.0.0.1/"]),
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
