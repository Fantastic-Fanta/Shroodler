from __future__ import annotations

from shroodler.extractors.html_markup import (
    extract_html_comments,
    extract_html_markup,
    extract_meta_generator,
    load_comment_keywords,
)


def _ids(findings) -> set[str]:
    return {f.id for f in findings}


def test_keywords_are_data_driven():
    keys = {k.upper() for k in load_comment_keywords()}
    assert {"TODO", "FIXME", "PASSWORD", "API_KEY"} <= keys


def test_todo_comment_is_verbose_error_info():
    html = "<html><body><!-- TODO: remove debug admin at /nope --></body></html>"
    findings = extract_html_comments(html, "http://127.0.0.1/")
    assert len(findings) == 1
    f = findings[0]
    assert f.id == "html-comment"
    assert f.category == "verbose-error"
    assert f.severity == "info"
    assert "TODO" in (f.evidence or "")


def test_fixme_password_and_api_key_comments():
    html = """<html><body>
    <!-- FIXME later -->
    <!-- PASSWORD leftover in template -->
    <!-- API_KEY=not-a-real-key -->
    </body></html>"""
    findings = extract_html_comments(html, "http://127.0.0.1/x")
    assert len(findings) == 3
    assert all(f.id == "html-comment" and f.category == "verbose-error" for f in findings)


def test_boring_layout_comment_is_ignored():
    html = "<html><body><!-- layout --><p>ok</p></body></html>"
    assert extract_html_comments(html, "http://127.0.0.1/about") == []


def test_comment_matching_secret_pattern_uses_secret_category():
    html = "<html><body><!-- TODO: AKIAIOSFODNN7EXAMPLE --></body></html>"
    findings = extract_html_comments(html, "http://127.0.0.1/")
    assert len(findings) == 1
    assert findings[0].id == "html-comment"
    assert findings[0].category == "secret"
    assert findings[0].severity == "info"


def test_meta_generator_is_header_info():
    html = '<html><head><meta name="generator" content="App1CMS 0.1.0"></head></html>'
    findings = extract_meta_generator(html, "http://127.0.0.1/")
    assert len(findings) == 1
    f = findings[0]
    assert f.id == "meta-generator"
    assert f.category == "header"
    assert f.severity == "info"
    assert f.evidence == "App1CMS 0.1.0"


def test_missing_generator_meta():
    html = '<html><head><meta name="viewport" content="width=device-width"></head></html>'
    assert extract_meta_generator(html, "http://127.0.0.1/") == []


def test_extract_html_markup_combines_both():
    html = """<html><head>
    <meta name="Generator" content="App1CMS 0.1.0">
    </head><body><!-- TODO: leftover --><!-- layout --></body></html>"""
    findings = extract_html_markup(html, "http://127.0.0.1/")
    assert _ids(findings) == {"html-comment", "meta-generator"}


def test_ie_conditional_comment_is_ignored():
    # Regression: a downlevel IE conditional comment (standard Showdown markup)
    # whose URL contains "auToDOwnload" used to match TODO via substring.
    html = (
        "<html><!--[if lte IE 8]><script>"
        "document.location.replace('http://pokemonshowdown.com/autodownload/win');"
        "</script><![endif]--></html>"
    )
    assert extract_html_comments(html, "http://127.0.0.1/") == []


def test_substring_keyword_is_not_a_hit():
    # "autodownload" contains "todo"; "author" contains "auth" -- neither is a
    # leftover dev note, so boundary-anchored matching must skip them.
    html = "<html><!-- autodownload scheduled; author notes --></html>"
    assert extract_html_comments(html, "http://127.0.0.1/") == []
