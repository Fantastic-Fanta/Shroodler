from __future__ import annotations

import json
from unittest.mock import MagicMock

from shroodler.agent import (
    AgentConfig,
    AuthzDiffAction,
    PeerWriteAction,
    decide_next_action,
)
from shroodler.llm_triage import local_rank_ids, triage_leads
from shroodler.models import Finding
from shroodler.program import ProgramState


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _endpoint(last_seen: str = "", tested_authz: bool = True, tested_peer: bool = False) -> dict:
    return {
        "last_seen": last_seen or _now_iso(),
        "tested_authz": tested_authz,
        "tested_peer_write": tested_peer,
        "tested_payload": False,
    }


def _config(**kwargs) -> AgentConfig:
    defaults = {
        "program": "lab",
        "target": "http://127.0.0.1/",
        "max_iterations": 3,
        "max_pages_per_crawl": 10,
        "dry_run": True,
        "owner_cookie": "session=owner",
        "peer_cookie": "session=peer",
        "llm_triage": True,
    }
    defaults.update(kwargs)
    return AgentConfig(**defaults)


def _state_with_ids() -> ProgramState:
    return ProgramState(
        slug="lab",
        endpoints={
            "http://127.0.0.1/api/users/1": _endpoint(),
        },
        object_ids={"/api/users/{id}": ["1", "2"]},
        findings=[
            Finding(
                id="authz-broken-access-control",
                severity="high",
                category="auth",
                url="http://127.0.0.1/api/users/1",
                description="must-not-appear-in-prompt secret@example.com",
                confidence="confirmed",
            )
        ],
    )


def _fake_anthropic(text: str):
    block = MagicMock()
    block.text = text
    message = MagicMock()
    message.content = [block]
    client = MagicMock()
    client.messages.create.return_value = message
    return client


def test_triage_returns_fallback_when_no_api_key(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")

    def _auth_error() -> Exception:
        import anthropic

        try:
            return anthropic.AuthenticationError("missing key")
        except TypeError:
            request = __import__("httpx").Request("GET", "https://api.anthropic.com")
            response = __import__("httpx").Response(401, request=request)
            return anthropic.AuthenticationError("missing key", response=response, body={})

    class Boom:
        def __init__(self, *args, **kwargs):
            raise _auth_error()

    monkeypatch.setattr("anthropic.Anthropic", Boom)
    ids = ["1", "2"]
    urls = ["http://127.0.0.1/api/a"]
    result = triage_leads(_state_with_ids(), ids, urls, _config())
    assert result.used_llm is False
    assert result.ranked_ids == ids
    assert result.ranked_urls == urls
    assert "fallback" in result.rationale


def test_triage_parses_ranked_response(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    payload = {
        "ranked_ids": ["2", "1"],
        "ranked_urls": ["http://127.0.0.1/api/b", "http://127.0.0.1/api/a"],
        "rationale": "integers first",
    }
    monkeypatch.setattr("anthropic.Anthropic", lambda *a, **k: _fake_anthropic(json.dumps(payload)))
    ids = ["1", "2"]
    urls = ["http://127.0.0.1/api/a", "http://127.0.0.1/api/b"]
    result = triage_leads(_state_with_ids(), ids, urls, _config())
    assert result.used_llm is True
    assert result.ranked_ids == ["2", "1"]
    assert result.ranked_urls == ["http://127.0.0.1/api/b", "http://127.0.0.1/api/a"]


def test_triage_falls_back_on_invalid_json(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setattr("anthropic.Anthropic", lambda *a, **k: _fake_anthropic("not json at all"))
    ids = ["1", "2"]
    urls = ["http://127.0.0.1/api/a"]
    result = triage_leads(_state_with_ids(), ids, urls, _config())
    assert result.used_llm is False
    assert result.ranked_ids == ids
    assert result.ranked_urls == urls


def test_triage_skipped_when_flag_off(monkeypatch):
    called = {"n": 0}

    def boom(*args, **kwargs):
        called["n"] += 1
        raise AssertionError("triage_leads must not be called when llm_triage is off")

    monkeypatch.setattr("shroodler.llm_triage.triage_leads", boom)
    state = _state_with_ids()
    action = decide_next_action(state, _config(llm_triage=False))
    assert called["n"] == 0
    assert isinstance(action, PeerWriteAction)
    assert action.object_ids == ["1", "2"]


def test_triage_logs_rationale(monkeypatch, capsys):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    payload = {
        "ranked_ids": ["2", "1"],
        "ranked_urls": [],
        "rationale": "sequential ids beat uuids",
    }
    monkeypatch.setattr("anthropic.Anthropic", lambda *a, **k: _fake_anthropic(json.dumps(payload)))
    state = _state_with_ids()
    action = decide_next_action(state, _config(llm_triage=True))
    err = capsys.readouterr().err
    assert "sequential ids beat uuids" in err
    assert isinstance(action, PeerWriteAction)
    assert action.object_ids == ["2", "1"]


def test_triage_detects_integer_ids_as_higher_priority():
    ranked = local_rank_ids(
        [
            "550e8400-e29b-41d4-a716-446655440000",
            "42",
            "user-slug",
            "7",
        ]
    )
    assert ranked[0] == "42"
    assert ranked[1] == "7"
    assert ranked[-1] == "550e8400-e29b-41d4-a716-446655440000"


def test_triage_prompt_omits_finding_descriptions(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    captured: dict[str, str] = {}

    class FakeClient:
        def __init__(self, *a, **k):
            self.messages = self

        def create(self, **kwargs):
            captured["user"] = kwargs["messages"][0]["content"]
            return _fake_anthropic(
                json.dumps({"ranked_ids": ["1"], "ranked_urls": [], "rationale": "ok"})
            )

    monkeypatch.setattr("anthropic.Anthropic", FakeClient)
    triage_leads(_state_with_ids(), ["1"], [], _config())
    prompt = captured["user"]
    assert "must-not-appear-in-prompt" not in prompt
    assert "secret@example.com" not in prompt
    assert "authz-broken-access-control" in prompt
    assert "high" in prompt


def test_triage_ranks_authz_urls(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    payload = {
        "ranked_ids": [],
        "ranked_urls": ["http://127.0.0.1/api/b"],
        "rationale": "write api first",
    }
    monkeypatch.setattr("anthropic.Anthropic", lambda *a, **k: _fake_anthropic(json.dumps(payload)))
    state = ProgramState(
        slug="lab",
        endpoints={
            "http://127.0.0.1/api/a": _endpoint(tested_authz=False),
            "http://127.0.0.1/api/b": _endpoint(tested_authz=False),
        },
    )
    action = decide_next_action(
        state,
        _config(
            owner_cookie=None,
            peer_cookie=None,
            higher_priv_jar="high.json",
            lower_priv_jar="low.json",
            llm_triage=True,
        ),
    )
    assert isinstance(action, AuthzDiffAction)
    assert action.urls[0] == "http://127.0.0.1/api/b"
    assert "http://127.0.0.1/api/a" in action.urls
