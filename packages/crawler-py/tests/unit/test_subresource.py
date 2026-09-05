from __future__ import annotations

from shroodler.crawler import crawl_url
from shroodler.extractors.subresource import extract_subresource_findings


def _ids(findings) -> set[str]:
    return {f.id for f in findings}


def test_cross_origin_script_without_integrity_is_flagged():
    html = '<html><head><script src="https://cdn.example.com/lib.js"></script></head></html>'
    findings = extract_subresource_findings(html, "https://app.example.org/")
    assert _ids(findings) == {"sri-missing"}
    assert findings[0].severity == "low"
    assert findings[0].category == "subresource"
    assert "cdn.example.com/lib.js" in (findings[0].evidence or "")


def test_cross_origin_script_with_integrity_is_not_flagged():
    html = (
        '<html><head><script src="https://cdn.example.com/lib.js" '
        'integrity="sha384-abc"></script></head></html>'
    )
    assert extract_subresource_findings(html, "https://app.example.org/") == []


def test_same_origin_script_is_not_flagged_even_without_integrity():
    html = '<html><head><script src="/static/app.js"></script></head></html>'
    assert extract_subresource_findings(html, "https://app.example.org/") == []


def test_stylesheet_link_without_integrity_is_flagged():
    html = (
        '<html><head><link rel="stylesheet" '
        'href="https://cdn.example.com/style.css"></head></html>'
    )
    findings = extract_subresource_findings(html, "https://app.example.org/")
    assert _ids(findings) == {"sri-missing"}


def test_non_stylesheet_link_is_ignored():
    html = (
        '<html><head><link rel="icon" href="https://cdn.example.com/favicon.ico">'
        "</head></html>"
    )
    assert extract_subresource_findings(html, "https://app.example.org/") == []


def test_https_page_loading_http_script_is_mixed_content():
    html = '<html><head><script src="http://app.example.org/lib.js"></script></head></html>'
    findings = extract_subresource_findings(html, "https://app.example.org/")
    ids = _ids(findings)
    assert "mixed-content" in ids
    mc = next(f for f in findings if f.id == "mixed-content")
    assert mc.severity == "medium"
    # http:// vs https:// is itself a different origin (same_origin compares
    # scheme too), so a downgraded-scheme subresource is correctly flagged
    # as both mixed-content and missing-SRI -- either one alone would let
    # an on-path attacker tamper with it.
    assert "sri-missing" in ids


def test_http_page_loading_http_script_is_not_mixed_content():
    html = '<html><head><script src="http://cdn.example.com/lib.js"></script></head></html>'
    findings = extract_subresource_findings(html, "http://app.example.org/")
    assert "mixed-content" not in _ids(findings)


def test_data_and_javascript_uri_scripts_are_ignored():
    html = (
        "<html><head>"
        '<script src="data:text/javascript,alert(1)"></script>'
        '<script src="javascript:void(0)"></script>'
        "</head></html>"
    )
    assert extract_subresource_findings(html, "https://app.example.org/") == []


def test_empty_body_returns_no_findings():
    assert extract_subresource_findings("", "https://app.example.org/") == []


def test_crawl_includes_subresource_findings_by_default(fx):
    # Always-on, unlike an opt-in flag: this is a real check, not a hidden
    # one nobody would think to enable. shroodler-go doesn't implement it
    # yet, so packages/parity-tests/run_parity.py excludes the
    # "subresource" category from its Python/Go comparison instead of this
    # check being gated behind a flag.
    fx.html(
        "/",
        '<html><head><script src="https://cdn.example.com/lib.js"></script></head></html>',
    )
    result = crawl_url(fx.origin + "/", depth=0)
    assert "sri-missing" in {f.id for f in result.findings}
