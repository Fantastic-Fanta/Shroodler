from __future__ import annotations

import json
from base64 import b64encode

from shroodler.crawler import crawl_url
from shroodler.extractors.js_endpoints import extract_js_endpoints
from shroodler.extractors.sourcemap import (
    decode_data_url,
    extract_from_source_map,
    parse_source_map,
    source_mapping_url,
)


def test_fetch_string_literal():
    eps, findings = extract_js_endpoints("/static/app.js", 'fetch("/api/internal/debug")')
    assert eps[0].endpoint == "/api/internal/debug"
    assert findings[0].id == "js-endpoint"


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


def test_source_mapping_url_comment():
    js = "function n(){}\n//# sourceMappingURL=app.min.js.map\n"
    assert source_mapping_url(js) == "app.min.js.map"


def test_extract_from_source_map_resolves_original():
    eps, findings = extract_from_source_map("/static/app.min.js", _map_obj())
    assert eps[0].endpoint == "/api/sourcemap-only"
    assert any("src/internal.ts" in (f.evidence or "") for f in findings)
    assert any("original src/internal.ts" in f.description for f in findings)


def test_inline_data_source_map(fx):
    payload = b64encode(json.dumps(_map_obj()).encode()).decode()
    js = f'function n(){{return 1}}\n//# sourceMappingURL=data:application/json;base64,{payload}\n'
    fx.html("/", '<script src="/app.min.js"></script>')
    fx.route(
        "/app.min.js",
        lambda _req: (200, {"Content-Type": "application/javascript"}, js.encode()),
    )
    result = crawl_url(fx.origin + "/", depth=2)
    assert any(e.endpoint == "/api/sourcemap-only" for e in result.js_endpoints)
    hit = next(f for f in result.findings if f.id == "js-endpoint")
    assert "src/internal.ts" in (hit.evidence or hit.description)


def test_fetched_source_map_not_in_minified(fx):
    fx.html("/", '<script src="/mapped.min.js"></script>')
    fx.route(
        "/mapped.min.js",
        lambda _req: (
            200,
            {"Content-Type": "application/javascript"},
            b"function n(){return 1}\n//# sourceMappingURL=mapped.min.js.map\n",
        ),
    )
    fx.route(
        "/mapped.min.js.map",
        lambda _req: (
            200,
            {"Content-Type": "application/json"},
            json.dumps(_map_obj()).encode(),
        ),
    )
    result = crawl_url(fx.origin + "/", depth=2)
    assert "/api/sourcemap-only" not in fx.origin
    assert any(e.endpoint == "/api/sourcemap-only" for e in result.js_endpoints)
    assert not any("/api/sourcemap-only" in (p.url or "") for p in result.pages)


def test_parse_and_data_url_helpers():
    assert parse_source_map("not-json") is None
    assert decode_data_url("nope") is None
    assert decode_data_url("data:text/plain,hello") == b"hello"
