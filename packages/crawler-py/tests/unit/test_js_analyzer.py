from __future__ import annotations

import base64
import json

from shroodler.js_analyzer import JSAnalyzer
from shroodler.program import ProgramState


SOURCE = "https://example.com/static/app.js"


def _state() -> ProgramState:
    return ProgramState(slug="lab")


def _paths(state: ProgramState) -> list[str]:
    out: list[str] = []
    for url in state.endpoints:
        out.append(url)
        path = url.split("://", 1)[-1]
        if "/" in path:
            out.append("/" + path.split("/", 1)[1])
    return out


def test_fetch_axios_xhr_endpoints_added_to_state():
    js = """
    fetch("/api/v1/accounts");
    axios.get(`/users/${userId}/profile`);
    var xhr = new XMLHttpRequest();
    xhr.open("GET", "/api/concat/" + "path");
    """
    state = _state()
    findings = JSAnalyzer().analyze(js, SOURCE, state)
    ids = [f.id for f in findings]
    assert ids.count("js-api-endpoint-found") >= 3
    blob = " ".join(_paths(state))
    assert "/api/v1/accounts" in blob
    assert "/users/{param}/profile" in blob
    assert "/api/concat/path" in blob
    for finding in findings:
        if finding.id == "js-api-endpoint-found":
            assert finding.severity == "info"
            assert finding.category == "js-endpoint"
            assert finding.confidence == "confirmed"


def test_hardcoded_secret_redacted():
    secret = "sk_live_abcdefghijklmnop"
    aws = "AKIAIOSFODNN7EXAMPLE"
    js = f'const apiKey = "{secret}"; const k = "{aws}";'
    findings = JSAnalyzer().analyze(js, SOURCE, _state())
    secrets = [f for f in findings if f.id == "js-hardcoded-secret"]
    assert len(secrets) >= 2
    evidence = " ".join(f.evidence or "" for f in secrets)
    assert secret not in evidence
    assert aws not in evidence
    assert "****" in evidence
    assert "sk_l****" in evidence or "apiKey=" in evidence or "apikey=" in evidence.lower()
    assert "AKIA****" in evidence
    for finding in secrets:
        assert finding.severity == "high"
        assert finding.category == "secret"
        assert secret not in (finding.description or "")
        assert aws not in (finding.description or "")


def test_jwt_atob_split_and_verify():
    js = """
    const parts = atob(token).split('.');
    jwt.verify(token, secret);
    """
    findings = JSAnalyzer().analyze(js, SOURCE, _state())
    hits = [f for f in findings if f.id == "js-client-side-jwt-decode"]
    assert len(hits) >= 2
    evidence = " ".join(f.evidence or "" for f in hits)
    assert "atob" in evidence
    assert "jwt.verify" in evidence
    assert all(len(f.evidence or "") <= 200 for f in hits)
    assert all(f.severity == "medium" for f in hits)


def test_graphql_query_and_mutation_unique():
    js = """
    query GetUser { user { id } }
    mutation UpdateUser { updateUser { id } }
    query GetUser { user { name } }
    """
    state = _state()
    findings = JSAnalyzer().analyze(js, SOURCE, state)
    ops = [f for f in findings if f.id == "js-graphql-operation"]
    names = {f.evidence for f in ops}
    assert names == {"GetUser", "UpdateUser"}
    assert "GetUser" in state.extra_graphql_operations
    assert "UpdateUser" in state.extra_graphql_operations
    assert state.extra_graphql_operations.count("GetUser") == 1


def test_inline_source_map_runs_nested_analyzers():
    inner = 'fetch("/api/from-map");'
    payload = {
        "version": 3,
        "sources": ["app.ts"],
        "sourcesContent": [inner],
        "mappings": "",
    }
    b64 = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
    js = f"console.log(1);\n//# sourceMappingURL=data:application/json;base64,{b64}"
    state = _state()
    findings = JSAnalyzer().analyze(js, SOURCE, state)
    assert any(f.id == "js-api-endpoint-found" for f in findings)
    assert any("/api/from-map" in u or u.endswith("/api/from-map") for u in _paths(state))
    assert not any(f.id == "js-source-map-found" for f in findings)


def test_relative_source_map_emits_finding():
    js = "console.log(1);\n//# sourceMappingURL=app.js.map\n"
    state = _state()
    findings = JSAnalyzer().analyze(js, SOURCE, state)
    hits = [f for f in findings if f.id == "js-source-map-found"]
    assert len(hits) == 1
    assert hits[0].severity == "info"
    assert "app.js.map" in (hits[0].evidence or "")
    assert any("app.js.map" in u for u in state.source_map_urls)


def test_duplicate_fetch_same_url_one_finding():
    js = 'fetch("/api/dup"); fetch("/api/dup");'
    findings = JSAnalyzer().analyze(js, SOURCE, _state())
    api = [f for f in findings if f.id == "js-api-endpoint-found"]
    assert len(api) == 1
    assert api[0].evidence == "/api/dup"


def test_empty_and_minimal_js_no_findings():
    analyzer = JSAnalyzer()
    assert analyzer.analyze("", SOURCE, _state()) == []
    assert analyzer.analyze("var x = 1;", SOURCE, _state()) == []


def test_skips_finding_when_endpoint_already_known():
    state = _state()
    state.endpoints["https://example.com/api/v1/accounts"] = {
        "tested_authz": False,
        "last_seen": "2026-01-01T00:00:00Z",
    }
    findings = JSAnalyzer().analyze('fetch("/api/v1/accounts");', SOURCE, state)
    assert not any(f.id == "js-api-endpoint-found" for f in findings)


def test_short_secret_value_downgraded_to_heuristic():
    from shroodler.js_analyzer import shannon_entropy

    js = 'const apiKey = "shortsecret12";'
    findings = JSAnalyzer().analyze(js, SOURCE, _state())
    secrets = [f for f in findings if f.id == "js-hardcoded-secret"]
    assert len(secrets) == 1
    assert secrets[0].severity == "medium"
    assert secrets[0].confidence == "heuristic"
    assert (secrets[0].evidence or "").startswith("[entropy-check-failed]")
    assert shannon_entropy("shortsecret12") >= 0


def test_low_entropy_secret_value_downgraded():
    js = 'const api_key = "abababababababab";'
    findings = JSAnalyzer().analyze(js, SOURCE, _state())
    secrets = [f for f in findings if f.id == "js-hardcoded-secret"]
    assert len(secrets) == 1
    assert secrets[0].severity == "medium"
    assert secrets[0].confidence == "heuristic"
    assert "entropy-check-failed" in (secrets[0].evidence or "")


def test_construction_secret_value_dropped_as_blocklist():
    js = 'const secret = "construction";'
    findings = JSAnalyzer().analyze(js, SOURCE, _state())
    assert not any(f.id == "js-hardcoded-secret" for f in findings)


def test_akia_pattern_flagged_without_entropy_downgrade():
    aws = "AKIAIOSFODNN7EXAMPLE"
    js = f'const k = "{aws}";'
    findings = JSAnalyzer().analyze(js, SOURCE, _state())
    secrets = [f for f in findings if f.id == "js-hardcoded-secret"]
    assert len(secrets) == 1
    assert secrets[0].severity == "high"
    assert secrets[0].confidence == "confirmed"
    assert "entropy-check-failed" not in (secrets[0].evidence or "")
    assert aws not in (secrets[0].evidence or "")


def test_angular_httpclient_rest_and_login_extracted():
    js = """
    this.http.get(`${this.hostServer}/rest/basket/${e}`).pipe();
    this.http.get(`${this.hostServer}/rest/products/search?q=${e}`).pipe();
    this.http.post(this.hostServer+`/rest/user/login`, e).pipe();
    this.http.get(this.hostServer+`/api/Users`).pipe();
    """
    state = _state()
    findings = JSAnalyzer().analyze(js, SOURCE, state)
    blob = " ".join(_paths(state))
    assert "/rest/basket/{param}" in blob or "/rest/basket/1" in blob
    assert "/rest/products/search" in blob
    search_meta = next(
        m for u, m in state.endpoints.items() if "/rest/products/search" in u
    )
    search_names = {
        p.get("name")
        for p in (search_meta.get("params") or [])
        if isinstance(p, dict)
    }
    assert "q" in search_names
    assert "/rest/user/login" in blob
    assert "/api/Users" in blob
    login_meta = next(
        m for u, m in state.endpoints.items() if "/rest/user/login" in u
    )
    assert str(login_meta.get("method") or "").upper() == "POST"
    names = {
        p.get("name")
        for p in (login_meta.get("params") or [])
        if isinstance(p, dict)
    }
    assert "email" in names
    assert any("basket/1" in u for u in state.endpoints)
    assert any(f.id == "js-api-endpoint-found" for f in findings)


def test_angular_product_reviews_put_extracted():
    js = """
    this.http.get(`${this.hostServer}/rest/products/search?q=${e}`).pipe();
    this.http.put(`${this.host}/${e}/reviews`, {message: review});
    """
    state = _state()
    JSAnalyzer().analyze(js, SOURCE, state)
    reviews = [
        (url, meta)
        for url, meta in state.endpoints.items()
        if "/rest/products/" in url and url.rstrip("/").endswith("/reviews")
    ]
    assert reviews
    assert any("/rest/products/{param}/reviews" in url for url, _ in reviews)
    for _url, meta in reviews:
        assert str(meta.get("method") or "").upper() == "PUT"
        names = {
            p.get("name")
            for p in (meta.get("params") or [])
            if isinstance(p, dict)
        }
        assert "message" in names
        locations = {
            str(p.get("in") or "")
            for p in (meta.get("params") or [])
            if isinstance(p, dict) and p.get("name") == "message"
        }
        assert "json" in locations
