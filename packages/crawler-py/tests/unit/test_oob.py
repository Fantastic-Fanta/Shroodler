from __future__ import annotations

import json
from datetime import timedelta
from types import SimpleNamespace

import httpx
import pytest

from shroodler.agent import AgentConfig, run_agent
from shroodler.cli import build_parser, cmd_agent
from shroodler.models import Finding
from shroodler.oob import (
    OOBBindError,
    OOBCollaborator,
    OOBError,
    OOBHit,
    OOBToken,
    confirm_oob,
    parse_listen,
)
from shroodler.pacer import Pacer
from shroodler.program import ProgramState, save
from shroodler.probes.sqli import probe_sqli
from shroodler.probes.ssrf import probe_ssrf
from shroodler.probes.xxe import probe_xxe


class FakeResp:
    def __init__(self, status=200, text="", elapsed=0.0):
        self.status_code = status
        self.text = text
        self.content = text.encode()
        self.elapsed = timedelta(seconds=elapsed)
        self.headers = {}


class FakeClient:
    def __init__(self, handler=None):
        self.handler = handler or (lambda *a, **k: FakeResp())
        self.calls = []

    def request(self, method, url, **kw):
        self.calls.append((method, url, kw))
        return self.handler(method, url, kw)

    def close(self):
        pass


def _listen_miss(timeout: float):
    return 54321, lambda: False


class _FakeCollab:
    def __init__(self, hit: OOBHit | None):
        self._hit = hit
        self.minted: list[OOBToken] = []

    def mint(self, prefix: str = "") -> OOBToken:
        token = f"{prefix}-tok" if prefix else "tok"
        url = f"http://127.0.0.1:9/{token}"
        minted = OOBToken(token=token, url=url)
        self.minted.append(minted)
        return minted

    def wait_for_hit(self, token: str, timeout: float = 3.0) -> OOBHit | None:
        if self._hit is None:
            return None
        return self._hit


def test_parse_listen_host_port():
    assert parse_listen("127.0.0.1:8765") == ("127.0.0.1", 8765)
    assert parse_listen("127.0.0.1:0") == ("127.0.0.1", 0)
    with pytest.raises(OOBError):
        parse_listen("no-port")
    with pytest.raises(OOBError):
        parse_listen("127.0.0.1:not-a-port")


def test_mint_unique_tokens_and_urls():
    collab = OOBCollaborator("127.0.0.1", 0, public_base="http://example.invalid")
    first = collab.mint("ssrf")
    second = collab.mint("ssrf")
    assert first.token != second.token
    assert first.url.startswith("http://example.invalid/")
    assert first.token in first.url
    assert second.token in second.url


def test_local_get_wait_for_hit():
    collab = OOBCollaborator("127.0.0.1", 0)
    collab.start()
    try:
        minted = collab.mint("t")
        host, port = collab.server_address
        resp = httpx.get(f"http://{host}:{port}/{minted.token}", timeout=2.0)
        assert resp.status_code == 200
        assert resp.text == "ok"
        hit = collab.wait_for_hit(minted.token, timeout=2.0)
        assert hit is not None
        assert hit.token == minted.token
        assert hit.method == "GET"
        assert minted.token in hit.path
        assert hit.remote
        assert confirm_oob(collab, minted.token, timeout=0.1) is not None
    finally:
        collab.stop()


def test_wait_for_hit_timeout_none():
    collab = OOBCollaborator("127.0.0.1", 0)
    minted = collab.mint()
    assert collab.wait_for_hit(minted.token, timeout=0) is None
    assert confirm_oob(collab, minted.token, timeout=0) is None


def test_hits_isolated_per_token():
    collab = OOBCollaborator("127.0.0.1", 0)
    collab.start()
    try:
        a = collab.mint("a")
        b = collab.mint("b")
        host, port = collab.server_address
        httpx.get(f"http://{host}:{port}/{a.token}", timeout=2.0)
        httpx.post(f"http://{host}:{port}/{a.token}/extra", content=b"x", timeout=2.0)
        assert collab.hits(a.token)
        assert collab.hits(b.token) == []
        assert collab.wait_for_hit(b.token, timeout=0) is None
        qs = httpx.get(f"http://{host}:{port}/x?oob={b.token}", timeout=2.0)
        assert qs.status_code == 200
        b_hit = collab.wait_for_hit(b.token, timeout=2.0)
        assert b_hit is not None
        assert b.token in (b_hit.path or "")
    finally:
        collab.stop()


def test_public_base_does_not_change_listen():
    collab = OOBCollaborator("127.0.0.1", 0, public_base="http://example.invalid/hook")
    collab.start()
    try:
        minted = collab.mint("p")
        assert minted.url.startswith("http://example.invalid/hook/")
        host, port = collab.server_address
        httpx.get(f"http://{host}:{port}/{minted.token}", timeout=2.0)
        assert collab.wait_for_hit(minted.token, timeout=2.0) is not None
        assert "tokens=" in collab.summary()
    finally:
        collab.stop()


def test_bind_failure_raises_oob_bind_error():
    collab = OOBCollaborator("127.0.0.1", 999999)
    with pytest.raises(OOBBindError):
        collab.start()


def test_ssrf_oob_callback_when_collaborator_hit():
    hit = OOBHit(
        token="ssrf-tok",
        method="GET",
        path="/ssrf-tok",
        remote="10.1.2.3",
        headers={"User-Agent": "x"},
        at="2026-09-10T00:00:00Z",
    )
    collab = _FakeCollab(hit)
    findings = probe_ssrf(
        "http://127.0.0.1/fetch",
        "GET",
        [{"name": "url", "value": "http://example.com"}],
        "",
        client=FakeClient(),
        pacer=Pacer(0),
        listen_fn=_listen_miss,
        oob_timeout=0,
        oob=collab,
    )
    found = next(f for f in findings if f.id == "ssrf-oob-callback")
    Finding.model_validate(found.model_dump())
    assert found.confidence == "confirmed"
    assert found.severity == "high"
    assert found.category == "payload"
    assert "10.1.2.3" in (found.evidence or "")
    assert "GET" in (found.evidence or "")
    assert "ssrf-tok" in (found.evidence or "")


def test_ssrf_no_callback_finding_without_hit():
    findings = probe_ssrf(
        "http://127.0.0.1/fetch",
        "GET",
        [{"name": "url", "value": "http://example.com"}],
        "",
        client=FakeClient(),
        pacer=Pacer(0),
        listen_fn=_listen_miss,
        oob_timeout=0,
        oob=_FakeCollab(None),
    )
    assert not any(f.id == "ssrf-oob-callback" for f in findings)


def test_xxe_oob_when_collaborator_hit():
    hit = OOBHit(
        token="xxe-tok",
        method="POST",
        path="/xxe-tok",
        remote="127.0.0.1",
        headers={},
        at="2026-09-10T00:00:00Z",
    )
    findings = probe_xxe(
        "http://127.0.0.1/xml",
        "POST",
        [],
        "",
        client=FakeClient(),
        pacer=Pacer(0),
        listen_fn=_listen_miss,
        oob_timeout=0,
        content_type="application/xml",
        oob=_FakeCollab(hit),
    )
    found = next(f for f in findings if f.id == "xxe-oob")
    Finding.model_validate(found.model_dump())
    assert found.confidence == "confirmed"
    assert "xxe-tok" in (found.evidence or "")
    assert "127.0.0.1" in (found.evidence or "")


def test_xxe_no_extra_finding_without_hit():
    findings = probe_xxe(
        "http://127.0.0.1/xml",
        "POST",
        [],
        "",
        client=FakeClient(lambda *a, **k: FakeResp(400, "no xml")),
        pacer=Pacer(0),
        listen_fn=_listen_miss,
        oob_timeout=0,
        content_type="application/xml",
        oob=_FakeCollab(None),
    )
    assert not any(f.id == "xxe-oob" for f in findings)


def test_sqli_oob_when_collaborator_hit():
    hit = OOBHit(
        token="sqli-tok",
        method="GET",
        path="/sqli-tok",
        remote="192.0.2.9",
        headers={},
        at="2026-09-10T00:00:00Z",
    )
    findings = probe_sqli(
        "http://127.0.0.1/search",
        "GET",
        [{"name": "q", "value": "test"}],
        "",
        client=FakeClient(),
        pacer=Pacer(0),
        oob=_FakeCollab(hit),
    )
    found = next(f for f in findings if f.id == "sqli-oob")
    Finding.model_validate(found.model_dump())
    assert found.confidence == "confirmed"
    assert found.severity == "high"
    assert found.category == "payload"
    assert "192.0.2.9" in (found.evidence or "")


def test_sqli_oob_silent_without_hit():
    findings = probe_sqli(
        "http://127.0.0.1/search",
        "GET",
        [{"name": "q", "value": "test"}],
        "",
        client=FakeClient(),
        pacer=Pacer(0),
        oob=_FakeCollab(None),
    )
    assert not any(f.id == "sqli-oob" for f in findings)


def test_program_state_save_excludes_collaborator(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    state = ProgramState(slug="lab")
    state.oob = OOBCollaborator("127.0.0.1", 0)
    path = save(state)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert "oob" not in data
    blob = json.dumps(data)
    assert "OOBCollaborator" not in blob
    assert "ThreadingHTTPServer" not in blob


def test_cmd_agent_oob_bind_failure_exits_2(monkeypatch, capsys):
    def boom(_config):
        raise OOBBindError("OOB collaborator failed to bind 127.0.0.1:1: denied")

    monkeypatch.setattr("shroodler.oob.start_from_config", boom)
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
            "127.0.0.1:1",
        ]
    )
    assert cmd_agent(args) == 2
    err = capsys.readouterr().err
    assert "OOB collaborator failed to bind" in err


def test_run_agent_starts_and_stops_collaborator(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    from shroodler.program import load

    load("lab")
    seen: dict = {}

    class _Collab:
        def start(self):
            seen["start"] = True

        def stop(self):
            seen["stop"] = True

    def fake_start(config):
        seen["listen"] = config.oob_listen
        seen["public"] = config.oob_public_url
        c = _Collab()
        c.start()
        return c

    monkeypatch.setattr("shroodler.oob.start_from_config", fake_start)
    monkeypatch.setattr(
        "shroodler.agent._run_agent_body",
        lambda config, probe_memory=None: SimpleNamespace(
            iterations=0, confirmed=0, log=[], state_path="", errors=[]
        ),
    )
    config = AgentConfig(
        program="lab",
        target="http://127.0.0.1/",
        oob=True,
        oob_listen="127.0.0.1:0",
        oob_public_url="http://example.invalid",
        dry_run=True,
        max_iterations=0,
    )
    run_agent(config)
    assert seen.get("start") is True
    assert seen.get("stop") is True
    assert seen.get("listen") == "127.0.0.1:0"
    assert getattr(config, "_oob", None) is None
