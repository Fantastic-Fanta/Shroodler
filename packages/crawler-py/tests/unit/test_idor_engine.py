from __future__ import annotations

from shroodler.agent import AgentConfig
from shroodler.idor_engine import (
    IDOREngine,
    collect_idor_targets,
    looks_like_idor_url,
)
from shroodler.pacer import Pacer
from shroodler.program import ProgramState

_LONG_A = "owner-resource-payload-AAAA"
_LONG_B = "peer-visible-payload-BBBB"
_SHORT = "tiny"


def _engine(endpoints: dict, **kw) -> IDOREngine:
    state = ProgramState(slug="lab", endpoints=endpoints)
    config = AgentConfig(
        program="lab",
        target="http://127.0.0.1/",
        idor_methods=list(kw.pop("idor_methods", None) or ["GET"]),
        scope_file=kw.pop("scope_file", None),
    )
    return IDOREngine(
        state,
        config,
        owner_headers=kw.pop("owner_headers", {"X-Role": "owner"}),
        owner_cookies=kw.pop("owner_cookies", {"sid": "OWNER"}),
        peer_headers=kw.pop("peer_headers", {"X-Role": "peer"}),
        peer_cookies=kw.pop("peer_cookies", {"sid": "PEER"}),
        pacer=Pacer(0),
    )


def _idor(findings):
    return [f for f in findings if f.id == "idor-cross-account"]


def test_looks_like_idor_numeric_uuid_base62():
    assert looks_like_idor_url("http://127.0.0.1/api/users/123")
    assert looks_like_idor_url(
        "http://127.0.0.1/api/users/550e8400-e29b-41d4-a716-446655440000"
    )
    assert looks_like_idor_url("http://127.0.0.1/api/users/" + "a" * 32)
    assert looks_like_idor_url("http://127.0.0.1/api/obj/Ab12Cd34")
    assert not looks_like_idor_url("http://127.0.0.1/api/users/12")
    assert not looks_like_idor_url("http://127.0.0.1/api/users/1")
    assert looks_like_idor_url("http://127.0.0.1/rest/basket/1")
    assert not looks_like_idor_url("http://127.0.0.1/api/obj/abcdefgh")
    assert not looks_like_idor_url("http://127.0.0.1/api/users/{id}")


def test_collect_skips_non_get_by_default():
    state = ProgramState(
        slug="lab",
        endpoints={
            "http://127.0.0.1/api/users/123": {"method": "POST"},
            "http://127.0.0.1/api/users/456": {"method": "GET"},
        },
    )
    config = AgentConfig(program="lab", target="http://127.0.0.1/")
    urls = [u for u, _m in collect_idor_targets(state, config)]
    assert "http://127.0.0.1/api/users/456" in urls
    assert "http://127.0.0.1/api/users/123" not in urls


def test_critical_identical_bodies(monkeypatch):
    engine = _engine({"http://127.0.0.1/api/users/123": {"method": "GET"}})

    def fake(self, url, headers, cookies, method="GET"):
        return 200, _LONG_A

    monkeypatch.setattr(IDOREngine, "_request", fake)
    hits = _idor(engine.run_sync())
    assert len(hits) == 1
    hit = hits[0]
    assert hit.severity == "critical"
    assert hit.category == "auth"
    assert hit.confidence == "confirmed"
    assert "owner=200" in (hit.evidence or "")
    assert "peer=200" in (hit.evidence or "")
    assert "OWNER" not in (hit.evidence or "")
    assert "PEER" not in (hit.evidence or "")
    assert 'Cookie: <session>' in hit.description
    assert "OWNER" not in hit.description
    assert not hasattr(hit, "reproduction") or hit.model_dump().get("reproduction") is None


def test_high_different_bodies(monkeypatch):
    engine = _engine({"http://127.0.0.1/api/users/123": {"method": "GET"}})

    def fake(self, url, headers, cookies, method="GET"):
        if cookies.get("sid") == "OWNER":
            return 200, _LONG_A
        return 200, _LONG_B

    monkeypatch.setattr(IDOREngine, "_request", fake)
    hits = _idor(engine.run_sync())
    assert len(hits) == 1
    assert hits[0].severity == "high"
    assert hits[0].confidence == "confirmed"


def test_medium_short_peer_body(monkeypatch):
    engine = _engine({"http://127.0.0.1/api/users/123": {"method": "GET"}})

    def fake(self, url, headers, cookies, method="GET"):
        if cookies.get("sid") == "OWNER":
            return 200, _LONG_A
        return 200, _SHORT

    monkeypatch.setattr(IDOREngine, "_request", fake)
    hits = _idor(engine.run_sync())
    assert len(hits) == 1
    assert hits[0].severity == "medium"


def test_no_idor_peer_403(monkeypatch):
    engine = _engine({"http://127.0.0.1/api/users/123": {"method": "GET"}})

    def fake(self, url, headers, cookies, method="GET"):
        if cookies.get("sid") == "OWNER":
            return 200, _LONG_A
        return 403, "denied"

    monkeypatch.setattr(IDOREngine, "_request", fake)
    assert _idor(engine.run_sync()) == []


def test_no_idor_peer_404(monkeypatch):
    engine = _engine({"http://127.0.0.1/api/users/123": {"method": "GET"}})

    def fake(self, url, headers, cookies, method="GET"):
        if cookies.get("sid") == "OWNER":
            return 200, _LONG_A
        return 404, "missing"

    monkeypatch.setattr(IDOREngine, "_request", fake)
    assert _idor(engine.run_sync()) == []


def test_network_error_fail_closed(monkeypatch):
    engine = _engine({"http://127.0.0.1/api/users/123": {"method": "GET"}})

    def fake(self, url, headers, cookies, method="GET"):
        return 0, ""

    monkeypatch.setattr(IDOREngine, "_request", fake)
    assert _idor(engine.run_sync()) == []


def test_dedup_same_url_pattern(monkeypatch):
    engine = _engine(
        {
            "http://127.0.0.1/api/users/123": {"method": "GET"},
            "http://127.0.0.1/api/users/456": {"method": "GET"},
        }
    )

    def fake(self, url, headers, cookies, method="GET"):
        return 200, _LONG_A

    monkeypatch.setattr(IDOREngine, "_request", fake)
    hits = _idor(engine.run_sync())
    assert len(hits) == 1


def test_uuid_endpoint_is_candidate(monkeypatch):
    uuid = "550e8400-e29b-41d4-a716-446655440000"
    url = f"http://127.0.0.1/api/users/{uuid}"
    engine = _engine({url: {"method": "GET"}})
    seen: list[str] = []

    def fake(self, req_url, headers, cookies, method="GET"):
        seen.append(req_url)
        return 200, _LONG_A

    monkeypatch.setattr(IDOREngine, "_request", fake)
    hits = _idor(engine.run_sync())
    assert url in seen
    assert len(hits) == 1
    assert hits[0].url == url


def test_enumeration_n_plus_one(monkeypatch):
    engine = _engine({"http://127.0.0.1/api/users/100": {"method": "GET"}})

    def fake(self, url, headers, cookies, method="GET"):
        if url.endswith("/100"):
            if cookies.get("sid") == "OWNER":
                return 200, _LONG_A
            return 403, "denied"
        if url.endswith("/101"):
            return 200, _LONG_B
        if cookies.get("sid") == "OWNER":
            return 200, _LONG_A
        return 403, "denied"

    monkeypatch.setattr(IDOREngine, "_request", fake)
    hits = _idor(engine.run_sync())
    assert any(f.url.endswith("/101") for f in hits)
    assert any("param_name=path-enum" in (f.evidence or "") for f in hits)
    assert any("object_id=101" in (f.evidence or "") for f in hits)
    for hit in hits:
        assert "OWNER" not in (hit.evidence or "")
        assert "PEER" not in (hit.evidence or "")


def test_enumeration_cap_five_extra_ids(monkeypatch):
    engine = _engine({"http://127.0.0.1/api/items/100": {"method": "GET"}})
    seen: list[str] = []

    def fake(self, url, headers, cookies, method="GET"):
        seen.append(url)
        return 403, "no"

    monkeypatch.setattr(IDOREngine, "_request", fake)
    engine.run_sync()
    extra = {u for u in seen if u != "http://127.0.0.1/api/items/100"}
    assert len(extra) == 5


def test_session_headers_go_to_matching_principal(monkeypatch):
    engine = _engine(
        {"http://127.0.0.1/api/users/123": {"method": "GET"}},
        owner_headers={"X-Role": "owner", "Authorization": "Bearer owner-tok"},
        owner_cookies={"sid": "OWNER"},
        peer_headers={"X-Role": "peer", "Authorization": "Bearer peer-tok"},
        peer_cookies={"sid": "PEER"},
    )
    calls: list[tuple[dict, dict]] = []

    def fake(self, url, headers, cookies, method="GET"):
        calls.append((dict(headers), dict(cookies)))
        return 200, _LONG_A

    monkeypatch.setattr(IDOREngine, "_request", fake)
    engine.run_sync()
    owner_calls = [c for c in calls if c[1].get("sid") == "OWNER"]
    peer_calls = [c for c in calls if c[1].get("sid") == "PEER"]
    assert owner_calls
    assert peer_calls
    assert owner_calls[0][0].get("X-Role") == "owner"
    assert owner_calls[0][0].get("Authorization") == "Bearer owner-tok"
    assert peer_calls[0][0].get("X-Role") == "peer"
    assert peer_calls[0][0].get("Authorization") == "Bearer peer-tok"
    assert all(c[0].get("X-Role") != "peer" for c in owner_calls)
    assert all(c[0].get("X-Role") != "owner" for c in peer_calls)


def test_request_fail_closed_on_transport_error(monkeypatch):
    engine = _engine({"http://127.0.0.1/api/users/123": {"method": "GET"}})

    def boom(*a, **k):
        raise ConnectionError("offline")

    monkeypatch.setattr("shroodler.probes.common.request", boom)
    status, body = engine._request(
        "http://127.0.0.1/api/users/123",
        {"X-Role": "owner"},
        {"sid": "OWNER"},
    )
    assert status == 0
    assert body == ""
