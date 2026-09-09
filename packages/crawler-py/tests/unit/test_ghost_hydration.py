from __future__ import annotations

from datetime import datetime, timezone

from shroodler.agent import (
    AgentConfig,
    ProbeAction,
    _JS_ANALYSIS_PROBE_RANK,
    _hydrate_ghost_routes,
    _probe_params,
    _probe_rank,
    _untested_probe_urls,
    execute_action,
)
from shroodler.pacer import Pacer
from shroodler.probes.common import normalize_params
from shroodler.program import ProgramState


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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
        "run_js_analysis": False,
    }
    defaults.update(kwargs)
    return AgentConfig(**defaults)


def _meta(**kwargs) -> dict:
    row = {
        "last_seen": _now_iso(),
        "tested_authz": True,
        "tested_peer_write": True,
        "tested_payload": False,
    }
    row.update(kwargs)
    return row


def test_hydrate_merges_openapi_params_into_endpoints():
    oa_url = "http://127.0.0.1/api/guilds/{id}"
    ghost = "http://127.0.0.1/api/guilds/123"
    oa_params = [
        {"name": "id", "in": "path", "type": "integer"},
        {"name": "verbose", "in": "query", "type": "boolean"},
    ]
    state = ProgramState(
        slug="lab",
        openapi_spec_url="http://127.0.0.1/openapi.json",
        openapi_endpoints=[
            {
                "url": oa_url,
                "method": "GET",
                "params": oa_params,
                "auth_required": True,
            }
        ],
        endpoints={
            ghost: _meta(source="js-analysis"),
        },
    )
    cfg = _config()
    _hydrate_ghost_routes(state, cfg)

    oa_meta = state.endpoints[oa_url]
    names = {p["name"] for p in oa_meta.get("params") or []}
    assert "id" in names
    assert "verbose" in names
    assert oa_meta.get("auth_required") is True

    ghost_meta = state.endpoints[ghost]
    ghost_names = {p["name"] for p in ghost_meta.get("params") or []}
    assert "id" in ghost_names
    assert "verbose" in ghost_names
    assert ghost_meta.get("source") == "js-analysis"
    assert ghost_meta.get("auth_required") is True
    assert getattr(cfg, "_ghost_hydrate_done") is True


def test_hydrate_numeric_path_gets_synthetic_id():
    ghost = "http://127.0.0.1/api/guilds/123"
    state = ProgramState(
        slug="lab",
        endpoints={ghost: _meta(source="js-analysis")},
    )
    _hydrate_ghost_routes(state, _config())
    params = state.endpoints[ghost].get("params") or []
    by_name = {p["name"]: p for p in params}
    assert "id" in by_name
    assert by_name["id"]["in"] == "path"
    assert by_name["id"]["type"] == "integer"
    assert by_name["id"]["value"] == "123"


def test_hydrate_without_openapi_spec_url():
    ghost = "http://127.0.0.1/users/1"
    state = ProgramState(
        slug="lab",
        endpoints={ghost: _meta(source="js-analysis")},
    )
    assert not state.openapi_spec_url
    _hydrate_ghost_routes(state, _config())
    names = {p["name"] for p in state.endpoints[ghost].get("params") or []}
    assert "id" in names


def test_untested_probe_urls_includes_hydrated_ghost():
    ghost = "http://127.0.0.1/api/guilds/123"
    crawled = "http://127.0.0.1/about"
    state = ProgramState(
        slug="lab",
        endpoints={
            crawled: _meta(),
            ghost: _meta(source="js-analysis"),
        },
    )
    cfg = _config(run_probes=True)
    _hydrate_ghost_routes(state, cfg)
    queued = _untested_probe_urls(state, cfg)
    assert ghost in queued
    assert queued[0] == ghost


def test_probe_rank_boosts_js_analysis():
    generic = _probe_rank("http://127.0.0.1/search", {"params": [{"name": "q"}]})
    ghost = _probe_rank(
        "http://127.0.0.1/api/guilds/123",
        {"source": "js-analysis", "params": [{"name": "id"}]},
    )
    assert ghost == _JS_ANALYSIS_PROBE_RANK
    assert ghost < generic
    token = _probe_rank(
        "http://127.0.0.1/sqlinjection",
        {"source": "js-analysis"},
    )
    assert token == 0


def test_normalize_params_extracts_path_and_skips_version():
    assert normalize_params(None) == []
    assert normalize_params([]) == []
    from_url = normalize_params([], url="http://127.0.0.1/api/v2/guilds/123")
    names = [p["name"] for p in from_url]
    assert names == ["id"]
    assert from_url[0]["in"] == "path"
    assert from_url[0]["type"] == "integer"
    braced = normalize_params([], url="http://127.0.0.1/accounts/{accountId}")
    assert braced[0]["name"] == "accountId"
    assert braced[0]["in"] == "path"
    existing = normalize_params(
        [{"name": "q", "in": "query"}],
        url="http://127.0.0.1/search/999?q=1",
    )
    assert [p["name"] for p in existing] == ["q", "id"]


def test_probe_params_gate_opens_after_hydration():
    ghost = "http://127.0.0.1/api/guilds/123"
    state = ProgramState(
        slug="lab",
        endpoints={ghost: _meta(source="js-analysis")},
    )
    _method, before = _probe_params(ghost, state.endpoints[ghost])
    assert before  # URL extraction is the safety net even pre-hydrate
    _hydrate_ghost_routes(state, _config())
    _method, after = _probe_params(ghost, state.endpoints[ghost])
    assert any(p["name"] == "id" for p in after)


def test_execute_probe_threads_login_cookies_for_js_ghost(monkeypatch):
    captured: dict = {}

    def fake_sqli(url, method, params, cookie, **kw):
        captured["url"] = url
        captured["params"] = list(params)
        captured["cookie"] = cookie
        return []

    monkeypatch.setattr("shroodler.probes.sqli.probe_sqli", fake_sqli)
    ghost = "http://127.0.0.1/api/guilds/123"
    state = ProgramState(
        slug="lab",
        login_cookies={"session": "owner-sess"},
        login_headers={"Authorization": "Bearer tok"},
        endpoints={ghost: _meta(source="js-analysis", method="GET")},
    )
    _hydrate_ghost_routes(state, _config())
    execute_action(
        ProbeAction(urls=[ghost]),
        state,
        _config(
            dry_run=False,
            probe_xss=False,
            probe_path_traversal=False,
            probe_jwt=False,
            probe_idor=False,
            run_ssrf=False,
            run_open_redirect=False,
            run_host_header=False,
            run_ssti=False,
            run_xxe=False,
            run_graphql=False,
            run_crlf=False,
            run_prototype_pollution=False,
            run_rate_limit=False,
            run_mass_assignment=False,
            run_websocket=False,
        ),
        pacer=Pacer(0),
    )
    assert captured["url"] == ghost
    assert any(p["name"] == "id" for p in captured["params"])
    assert "session=owner-sess" in captured["cookie"]
    assert state.endpoints[ghost]["tested_payload"] is True
