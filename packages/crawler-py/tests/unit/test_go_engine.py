"""Unit tests for the Go-engine subprocess seam (go_engine.py).

These are CI-safe: subprocess is mocked, so no shroodler-go binary is required.
"""

from __future__ import annotations

import json
import subprocess
import types
from pathlib import Path

import pytest

from shroodler import go_engine


def test_crawl_args_maps_options():
    args = go_engine._crawl_args(
        "http://127.0.0.1:8081/",
        mode="headless",
        max_pages=50,
        depth=3,
        max_time=None,
        ignore_robots=True,
        no_sitemap=False,
        allow_external=True,
        check_rate_limit=False,
        headers={"X-A": "1"},
        user_agent="ua",
        cookie="k=v",
        cookie_jar=None,
        storage_state="/tmp/state.json",
        login_recipe=None,
        proxy=None,
        output="/tmp/out.json",
    )
    assert args[:2] == ["crawl", "http://127.0.0.1:8081/"]
    assert "--output" in args and "/tmp/out.json" in args
    assert "--mode" in args and "headless" in args
    assert "--max-pages" in args and "50" in args
    assert "--depth" in args and "3" in args
    assert "--ignore-robots" in args
    assert "--allow-external" in args
    assert "--no-sitemap" not in args  # False -> omitted
    assert "--check-rate-limit" not in args
    assert "--header" in args and "X-A: 1" in args
    assert "--user-agent" in args and "ua" in args
    assert "--cookie" in args and "k=v" in args
    assert "--storage-state" in args and "/tmp/state.json" in args


def test_find_binary_missing(monkeypatch, tmp_path):
    monkeypatch.setenv("SHROODLER_GO_BIN", str(tmp_path / "nope"))
    with pytest.raises(go_engine.GoEngineError):
        go_engine.find_go_binary()
    assert go_engine.available() is False


def test_find_binary_env_override(monkeypatch, tmp_path):
    fake = tmp_path / "shroodler-go"
    fake.write_text("#!/bin/sh\n")
    monkeypatch.setenv("SHROODLER_GO_BIN", str(fake))
    assert go_engine.find_go_binary() == fake
    assert go_engine.available() is True


def _fake_run_factory(document, returncode=0, stderr=""):
    def _fake_run(cmd, **kwargs):
        # emulate the binary writing its report to the --output path
        out = cmd[cmd.index("--output") + 1]
        if returncode == 0:
            Path(out).write_text(json.dumps(document), encoding="utf-8")
        return types.SimpleNamespace(returncode=returncode, stdout="", stderr=stderr)

    return _fake_run


def test_crawl_parses_report(monkeypatch, tmp_path):
    doc = {"target": "http://127.0.0.1:8081/", "pages": [{"url": "/"}], "findings": []}
    monkeypatch.setattr(go_engine.subprocess, "run", _fake_run_factory(doc))
    result = go_engine.crawl("http://127.0.0.1:8081/", binary=tmp_path / "shroodler-go")
    assert result == doc


def test_crawl_nonzero_exit_raises(monkeypatch, tmp_path):
    monkeypatch.setattr(
        go_engine.subprocess, "run", _fake_run_factory({}, returncode=2, stderr="boom")
    )
    with pytest.raises(go_engine.GoEngineError, match="exited 2"):
        go_engine.crawl("http://127.0.0.1:8081/", binary=tmp_path / "shroodler-go")


def test_crawl_timeout_raises(monkeypatch, tmp_path):
    def _boom(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, 1.0)

    monkeypatch.setattr(go_engine.subprocess, "run", _boom)
    with pytest.raises(go_engine.GoEngineError, match="timed out"):
        go_engine.crawl("http://127.0.0.1:8081/", binary=tmp_path / "shroodler-go")


def test_execute_crawl_uses_go_engine_when_selected(monkeypatch):
    """engine='go' routes _execute_crawl through go_engine.crawl, not crawl_url."""
    from shroodler import agent_exec
    from shroodler.agent_types import AgentConfig, CrawlAction
    from shroodler.pacer import Pacer
    from shroodler.program import ProgramState

    target = "http://127.0.0.1:8081/"
    doc = {
        "target": target,
        "pages": [{"url": target}],
        "findings": [
            {"id": "missing-csp", "url": target, "severity": "info", "evidence": "x"}
        ],
    }
    calls = {"go": 0, "py": 0}

    def _fake_go_crawl(url, **kwargs):
        calls["go"] += 1
        return doc

    def _boom_crawl_url(*a, **k):
        calls["py"] += 1
        raise AssertionError("crawl_url must not be called when engine='go'")

    monkeypatch.setattr(go_engine, "available", lambda: True)
    monkeypatch.setattr(go_engine, "crawl", _fake_go_crawl)
    monkeypatch.setattr("shroodler.crawler.crawl_url", _boom_crawl_url)

    state = ProgramState(slug="t")
    cfg = AgentConfig(program="t", target=target, engine="go")
    out = agent_exec._execute_crawl(CrawlAction(urls=[target]), state, cfg, Pacer(0))

    assert calls["go"] == 1 and calls["py"] == 0
    assert out["pages_crawled"] >= 1
    assert target in state.endpoints


def test_execute_crawl_go_collapses_systemic_header_findings(monkeypatch):
    """The Go path dedups per-response header findings to match the Python crawler."""
    import shroodler.agent  # noqa: F401  (load first for import order)
    from shroodler import agent_exec
    from shroodler.agent_types import AgentConfig, CrawlAction
    from shroodler.pacer import Pacer
    from shroodler.program import ProgramState

    origin = "http://127.0.0.1:8081"
    # Go emits the same header finding once per page; three pages here.
    doc = {
        "target": origin + "/",
        "pages": [{"url": f"{origin}/{p}"} for p in ("", "a", "b")],
        "findings": [
            {"id": "server-version-leak", "category": "header", "url": f"{origin}/{p}",
             "severity": "info", "evidence": "Server: nginx/1.0"}
            for p in ("", "a", "b")
        ],
    }
    monkeypatch.setattr(go_engine, "available", lambda: True)
    monkeypatch.setattr(go_engine, "crawl", lambda url, **k: doc)

    state = ProgramState(slug="t")
    cfg = AgentConfig(program="t", target=origin + "/", engine="go")
    agent_exec._execute_crawl(CrawlAction(urls=[origin + "/"]), state, cfg, Pacer(0))

    svl = [f for f in state.findings if f.id == "server-version-leak"]
    assert len(svl) == 1, f"expected the 3 per-page findings collapsed to 1, got {len(svl)}"
