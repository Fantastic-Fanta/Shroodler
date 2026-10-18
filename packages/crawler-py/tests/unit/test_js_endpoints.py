from __future__ import annotations

from shroodler.extractors.js_endpoints import extract_js_endpoints, ghost_route_findings
from shroodler.extractors.sourcemap import (
    decode_data_url,
    extract_from_source_map,
    parse_source_map,
    source_mapping_url,
)
from shroodler.models import JsEndpoint, Page


def test_fetch_string_literal():
    eps, findings = extract_js_endpoints("/static/app.js", 'fetch("/api/internal/debug")')
    assert eps[0].endpoint == "/api/internal/debug"
    assert findings[0].id == "js-endpoint"


def test_axios_method_calls():
    js = (
        'axios.get("/api/users");'
        'axios.post("/api/users", data);'
        'axios.delete("/api/users/1");'
    )
    eps, _ = extract_js_endpoints("/app.js", js)
    endpoints = {e.endpoint for e in eps}
    assert {"/api/users", "/api/users/1"} <= endpoints


def test_jquery_shorthand_and_ajax_object():
    js = (
        '$.get("/api/list", cb);'
        '$.post("/api/save", data);'
        '$.ajax({url: "/api/config", method: "GET"});'
    )
    eps, _ = extract_js_endpoints("/app.js", js)
    endpoints = {e.endpoint for e in eps}
    assert {"/api/list", "/api/save", "/api/config"} <= endpoints


def test_xhr_open_call():
    js = 'var x = new XMLHttpRequest(); x.open("GET", "/api/legacy");'
    eps, _ = extract_js_endpoints("/app.js", js)
    endpoints = {e.endpoint for e in eps}
    assert "/api/legacy" in endpoints


def test_template_literal_best_effort():
    eps, _ = extract_js_endpoints("/static/app.js", "fetch(`/api/session`)")
    assert eps[0].endpoint == "/api/session"


def test_minified_js():
    js = 'function x(){fetch("/a");fetch("/b")}'
    eps, _ = extract_js_endpoints("/m.js", js)
    assert {e.endpoint for e in eps} == {"/a", "/b"}


def _map_obj() -> dict:
    return {
        "version": 3,
        "file": "app.min.js",
        "sources": ["src/internal.ts"],
        "sourcesContent": ['fetch("/api/sourcemap-only");\n'],
        "mappings": "AAAA",
    }


def _page(url: str) -> Page:
    return Page(url=url, status_code=200)


def test_websocket_and_eventsource_literals():
    js = 'new WebSocket("/ws/live"); new EventSource("/sse/events");'
    eps, findings = extract_js_endpoints("/static/realtime.js", js)
    assert {e.endpoint for e in eps} == {"/ws/live", "/sse/events"}
    assert {f.id for f in findings} == {"js-endpoint"}

def test_ws_scheme_literals_same_host():
    js = 'const a = "ws://127.0.0.1:8081/ws/live"; const b = \'wss://127.0.0.1:8081/ws/live\';'
    eps, _ = extract_js_endpoints("http://127.0.0.1:8081/static/app.js", js)
    assert {e.endpoint for e in eps} == {
        "ws://127.0.0.1:8081/ws/live",
        "wss://127.0.0.1:8081/ws/live",
    }

def test_websocket_template_literal_best_effort():
    js = "new WebSocket(`/ws/tpl`); new EventSource(`/sse/tpl`);"
    eps, _ = extract_js_endpoints("/static/app.js", js)
    assert {e.endpoint for e in eps} == {"/ws/tpl", "/sse/tpl"}

def test_minified_websocket_oneliner():
    js = 'function x(){new WebSocket("/ws");new EventSource("/sse")}'
    eps, _ = extract_js_endpoints("/m.js", js)
    assert {e.endpoint for e in eps} == {"/ws", "/sse"}

def test_garbage_js_does_not_crash():
    garbage = "\x00\xff{{{ not javascript " + "new WebSocket(" + "'" * 50
    eps, findings = extract_js_endpoints("/g.js", garbage)
    assert eps == []
    assert findings == []

def test_ghost_route_unvisited_same_origin():
    origin = "http://127.0.0.1:8081/"
    src = "http://127.0.0.1:8081/static/app.js"
    findings = ghost_route_findings(
        origin,
        [_page(src)],
        [JsEndpoint(source=src, endpoint="/api/never-crawled-ghost")],
    )
    assert len(findings) == 1
    assert findings[0].id == "ghost-route"
    assert findings[0].category == "js-endpoint"
    assert findings[0].url.endswith("/api/never-crawled-ghost")
    assert findings[0].description == "endpoint mentioned in JS but never crawled"
    assert findings[0].evidence == src

def test_ghost_route_skipped_if_page_visited():
    origin = "http://127.0.0.1:8081/"
    src = "http://127.0.0.1:8081/static/app.js"
    visited = "http://127.0.0.1:8081/api/never-crawled-ghost"
    findings = ghost_route_findings(
        origin,
        [_page(src), _page(visited)],
        [JsEndpoint(source=src, endpoint="/api/never-crawled-ghost")],
    )
    assert findings == []

def test_ghost_route_skips_cross_origin():
    origin = "http://127.0.0.1:8081/"
    src = "http://127.0.0.1:8081/static/app.js"
    findings = ghost_route_findings(
        origin,
        [_page(src)],
        [JsEndpoint(source=src, endpoint="https://evil.example/api/x")],
    )
    assert findings == []

def test_source_mapping_url_comment():
    js = "function n(){}\n//# sourceMappingURL=app.min.js.map\n"
    assert source_mapping_url(js) == "app.min.js.map"


def test_extract_from_source_map_resolves_original():
    eps, findings = extract_from_source_map("/static/app.min.js", _map_obj())
    assert eps[0].endpoint == "/api/sourcemap-only"
    assert any("src/internal.ts" in (f.evidence or "") for f in findings)
    assert any("original src/internal.ts" in f.description for f in findings)


def test_parse_and_data_url_helpers():
    assert parse_source_map("not-json") is None
    assert decode_data_url("nope") is None
    assert decode_data_url("data:text/plain,hello") == b"hello"


def test_bare_api_path_literals_from_minified_bundle():
    # Minified SPA: paths stored as constants, called through variables. The
    # call-syntax patterns miss these, but the bare-path pass must catch them.
    js = 'const R={a:"/api/community",b:"/api/me/saves",c:`/api/cnd/raw-mesh/`};let f=R.a;h.get(f)'
    eps, _ = extract_js_endpoints("https://x.test/assets/app.js", js)
    paths = {e.endpoint for e in eps}
    assert "/api/community" in paths
    assert "/api/me/saves" in paths
    assert "/api/cnd/raw-mesh/" in paths


def test_bare_path_pass_ignores_static_assets():
    # Precision: static/asset/route paths must NOT be pulled in by the bare pass.
    js = 'x="/assets/index-abc.js";y="/static/logo.png";z="/favicon.svg";w="/home/about"'
    eps, _ = extract_js_endpoints("https://x.test/assets/app.js", js)
    assert eps == []


def test_extract_skips_comment_fragments():
    from shroodler.extractors.js_endpoints import extract_js_endpoints

    js = 'x("/* assert on the output */\\n\\n"); fetch("/api/real")'
    endpoints, _ = extract_js_endpoints("https://t/app.js", js)
    paths = [e.endpoint for e in endpoints]
    assert "/api/real" in paths
    assert not any("assert" in p for p in paths)
