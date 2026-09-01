from __future__ import annotations

from shroodler.extractors.js_endpoints import extract_js_endpoints


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
