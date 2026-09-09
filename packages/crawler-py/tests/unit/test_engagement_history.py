from __future__ import annotations

from shroodler.agent import AgentConfig, DiffAction, decide_next_action
from shroodler.engagement_history import (
    diff_endpoints,
    is_suppressed,
    record_suppression,
    surface_changes,
)
from shroodler.program import ProgramState, load, load_suppressions, record_run_summary, save


def test_diff_endpoints():
    old = {
        "http://127.0.0.1/a": {"params": [{"name": "q"}]},
        "http://127.0.0.1/gone": {"params": []},
        "http://127.0.0.1/same": {"params": [{"name": "id"}]},
    }
    new = {
        "http://127.0.0.1/a": {"params": [{"name": "q"}, {"name": "page"}]},
        "http://127.0.0.1/new": {"params": []},
        "http://127.0.0.1/same": {"params": [{"name": "id"}]},
    }
    diff = diff_endpoints(old, new)
    assert diff.added == ["http://127.0.0.1/new"]
    assert diff.removed == ["http://127.0.0.1/gone"]
    assert len(diff.param_changed) == 1
    assert diff.param_changed[0]["url"] == "http://127.0.0.1/a"
    assert "page" in diff.param_changed[0]["new"]


def test_record_suppression():
    state = ProgramState(slug="lab")
    record_suppression(state, "new-endpoint", "http://127.0.0.1/x", "accepted noise")
    assert len(state.suppressed_findings) == 1
    row = state.suppressed_findings[0]
    assert row["id"] == "new-endpoint"
    assert row["url"] == "http://127.0.0.1/x"
    assert row["reason"] == "accepted noise"
    assert row["suppressed_at"]


def test_is_suppressed():
    state = ProgramState(slug="lab")
    record_suppression(state, "sqli", "http://127.0.0.1/search", "fp")
    record_suppression(state, "xss", "*", "global")
    assert is_suppressed(state, "sqli", "http://127.0.0.1/search")
    assert not is_suppressed(state, "sqli", "http://127.0.0.1/other")
    assert is_suppressed(state, "xss", "http://127.0.0.1/any")
    assert not is_suppressed(state, "missing-csp", "http://127.0.0.1/search")


def test_surface_changes():
    diff = diff_endpoints(
        {
            "http://127.0.0.1/old": {"params": [{"name": "a"}]},
            "http://127.0.0.1/gone": {"params": []},
        },
        {
            "http://127.0.0.1/new": {"params": []},
            "http://127.0.0.1/old": {"params": [{"name": "a"}, {"name": "b"}]},
        },
    )
    findings = surface_changes(diff)
    ids = {f.id for f in findings}
    assert ids == {"new-endpoint", "removed-endpoint", "param-changed"}
    for finding in findings:
        assert finding.category == "scan-note"
        assert finding.severity == "info"
        assert finding.confidence == "heuristic"


def test_state_roundtrip_suppressions_and_history(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    state = load("lab")
    record_suppression(state, "sqli", "*", "noise")
    record_run_summary(
        state,
        {"started_at": "2026-09-09T00:00:00Z", "iterations": 3, "confirmed": 1, "new_endpoints": 4},
    )
    state.endpoints["http://127.0.0.1/a"] = {
        "first_seen": "2026-09-01T00:00:00Z",
        "last_seen": "2026-09-09T00:00:00Z",
        "param_history": [{"seen": "2026-09-01T00:00:00Z", "params": ["q"]}],
        "params": [{"name": "q"}],
    }
    save(state)
    reloaded = load("lab")
    assert load_suppressions(reloaded) == {("sqli", "*")}
    assert len(reloaded.run_history) == 1
    assert reloaded.run_history[0]["new_endpoints"] == 4
    assert reloaded.endpoints["http://127.0.0.1/a"]["first_seen"] == "2026-09-01T00:00:00Z"
    assert reloaded.endpoints["http://127.0.0.1/a"]["param_history"][0]["params"] == ["q"]


def test_param_history_appends_on_name_change(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    from shroodler.program import merge_crawl_doc

    state = load("lab")
    merge_crawl_doc(
        state,
        {
            "scan_finished_at": "2026-09-01T00:00:00Z",
            "pages": [{"url": "http://127.0.0.1/search", "params": ["q"]}],
        },
    )
    merge_crawl_doc(
        state,
        {
            "scan_finished_at": "2026-09-02T00:00:00Z",
            "pages": [{"url": "http://127.0.0.1/search", "params": ["q", "page"]}],
        },
    )
    hist = state.endpoints["http://127.0.0.1/search"]["param_history"]
    assert len(hist) == 2
    assert set(hist[-1]["params"]) == {"q", "page"}


def test_decide_diff_when_run_diff_and_crawl_done():
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    state = ProgramState(
        slug="lab",
        endpoints={
            "http://127.0.0.1/a": {
                "last_seen": now,
                "tested_authz": True,
                "tested_peer_write": True,
            }
        },
    )
    action = decide_next_action(
        state,
        AgentConfig(program="lab", target="http://127.0.0.1/", run_diff=True),
    )
    assert isinstance(action, DiffAction)


def test_engagement_cli_parses():
    from shroodler.cli import build_parser

    p = build_parser()
    args = p.parse_args(
        [
            "suppress",
            "--program",
            "lab",
            "--id",
            "sqli",
            "--url",
            "*",
            "--reason",
            "fp",
        ]
    )
    assert args.func.__name__ == "cmd_suppress"
    assert args.program == "lab"
    assert args.finding_id == "sqli"
    hist = p.parse_args(["engagement-history", "--program", "lab"])
    assert hist.func.__name__ == "cmd_engagement_history"
    diff = p.parse_args(["engagement-diff", "--program", "lab"])
    assert diff.func.__name__ == "cmd_engagement_diff"
    existing = p.parse_args(["history", "list"])
    assert existing.func.__name__ == "cmd_history_list"
    expiring = p.parse_args(["suppress", "expiring", "--days", "7"])
    assert expiring.func.__name__ == "cmd_suppress_expiring"
