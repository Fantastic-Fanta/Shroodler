from __future__ import annotations

from shroodler.extractors.js_routes import extract_js_routes, extract_js_routes_file


def test_extracts_brace_dollar_colon_and_django_placeholders():
    js = """
    const a = "/collections/{collectionId}/edit";
    const b = `/users/${userId}/settings`;
    axios.get("/photos/:photoId/tags");
    fetch("/items/<int:pk>/");
    const noise = "color: {red}; :hover { color: blue }";
    """
    routes = extract_js_routes("app.js", js)
    templates = {r["template"] for r in routes}
    assert "/collections/{collectionId}/edit" in templates
    assert "/users/{userId}/settings" in templates
    assert "/photos/{photoId}/tags" in templates
    assert "/items/{pk}/" in templates
    assert all(r["params"] for r in routes)


def test_dedupes_and_skips_empty():
    assert extract_js_routes("x.js", "") == []
    js = 'fetch("/api/{id}"); fetch("/api/{id}");'
    routes = extract_js_routes("x.js", js)
    assert len(routes) == 1
    assert routes[0]["params"] == ["id"]


def test_file_wrapper(tmp_path):
    p = tmp_path / "nB.js"
    p.write_text('nB.uploadFile=function(e){return "/accounts/media/{photoId}/"}', encoding="utf-8")
    out = extract_js_routes_file(p)
    assert out["source"] == str(p)
    assert out["routes"][0]["template"] == "/accounts/media/{photoId}/"
