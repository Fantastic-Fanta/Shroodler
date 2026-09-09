from __future__ import annotations

from shroodler.webgoat import (
    captured_endpoint,
    is_webgoat_url,
    keep_captured,
    lesson_nav_url,
    lesson_nav_urls,
    params_from_request,
    parse_lesson_menu,
    start_mvc_url,
    webgoat_prefix,
)


def test_is_webgoat_url():
    assert is_webgoat_url("http://localhost:8080/WebGoat/start.mvc")
    assert is_webgoat_url("http://127.0.0.1:8080/WebGoat")
    assert not is_webgoat_url("http://localhost:8080/")
    assert not is_webgoat_url("http://localhost:8080/WebGoatish")


def test_webgoat_prefix_and_start_mvc():
    url = "http://localhost:8080/WebGoat/start.mvc#SqlInjection"
    assert webgoat_prefix(url) == "http://localhost:8080/WebGoat"
    assert start_mvc_url(url) == "http://localhost:8080/WebGoat/start.mvc"


def test_parse_lesson_menu_collects_leaf_links():
    menu = [
        {
            "name": "A1 Injection",
            "children": [
                {"name": "SQL Injection (intro)", "link": "SqlInjection.lesson"},
                {
                    "name": "nested",
                    "children": [{"name": "XSS", "link": "#XSS"}],
                },
            ],
        },
        {"name": "JWT", "link": "JWT"},
    ]
    assert parse_lesson_menu(menu) == ["SqlInjection.lesson", "#XSS", "JWT"]


def test_lesson_nav_url_variants():
    base = "http://localhost:8080/WebGoat"
    assert lesson_nav_url(base, "SqlInjection") == (
        "http://localhost:8080/WebGoat/start.mvc#SqlInjection"
    )
    assert lesson_nav_url(base, "#XSS") == "http://localhost:8080/WebGoat/start.mvc#XSS"
    assert lesson_nav_url(base, "SqlInjection.lesson/SqlInjection") == (
        "http://localhost:8080/WebGoat/start.mvc#SqlInjection"
    )
    assert lesson_nav_url(base, "/WebGoat/PathTraversal.lesson") == (
        "http://localhost:8080/WebGoat/PathTraversal.lesson"
    )


def test_lesson_nav_urls_dedupes():
    urls = lesson_nav_urls(
        "http://localhost:8080/WebGoat",
        ["SqlInjection", "#SqlInjection", "SqlInjection.lesson"],
    )
    assert urls == ["http://localhost:8080/WebGoat/start.mvc#SqlInjection"]


def test_params_from_request_query_and_form_body():
    params = params_from_request(
        "http://localhost:8080/WebGoat/SqlInjection/attack2?from=menu",
        "POST",
        post_data="username=guest&password=guest",
        content_type="application/x-www-form-urlencoded",
    )
    names = {p["name"]: p for p in params}
    assert names["from"]["in"] == "query"
    assert names["username"]["value"] == "guest"
    assert names["username"]["in"] == "body"


def test_params_from_json_body():
    params = params_from_request(
        "http://localhost:8080/WebGoat/JWT/login",
        "POST",
        post_data='{"user":"webgoat","pass":"webgoat"}',
        content_type="application/json",
    )
    assert {p["name"] for p in params} == {"user", "pass"}


def test_keep_captured_drops_static_and_document_get():
    assert keep_captured("http://x/WebGoat/a.js", "GET", "script") is False
    assert keep_captured("http://x/WebGoat/start.mvc", "GET", "document") is False
    assert keep_captured("http://x/WebGoat/SqlInjection/attack2", "POST", "xhr") is True
    assert keep_captured("http://x/WebGoat/SqlInjection/lesson", "GET", "fetch") is True


def test_captured_endpoint_strips_query():
    rec = captured_endpoint(
        "http://x/WebGoat/SqlInjection/lesson?from=menu",
        "GET",
        resource_type="fetch",
    )
    assert rec is not None
    assert rec["url"] == "http://x/WebGoat/SqlInjection/lesson"
    assert rec["params"][0]["name"] == "from"
