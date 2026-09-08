from __future__ import annotations

from shroodler.csrf import (
    apply_csrf,
    extract_csrf_tokens,
    looks_like_csrf_rejection,
    prefer_token,
    refresh_csrf,
)
from shroodler.extractors.csrf import csrf_findings
from shroodler.models import Cookie, Form, FormField, Page


def test_extract_prefers_hidden_form_field():
    html = """
    <form method="post">
      <input type="hidden" name="csrf_token" value="form-tok-12345678">
    </form>
    <meta name="csrf-token" content="meta-tok-12345678">
    <script>window.Flourish.csrf_token = "js-tok-12345678";</script>
    """
    tokens = extract_csrf_tokens(html, cookie_header="csrftoken=cookie-tok-12345678")
    assert prefer_token(tokens).source == "form"
    assert prefer_token(tokens).value == "form-tok-12345678"


def test_extract_js_and_cookie_fallbacks():
    html = '<script>window.App.csrf_token = "js-tok-abcdefgh";</script>'
    tokens = extract_csrf_tokens(html, cookie_header="XSRF-TOKEN=cookie-tok-abcdefgh")
    sources = {t.source for t in tokens}
    assert "js" in sources
    assert "cookie" in sources


def test_apply_csrf_json_and_headers():
    token = prefer_token(extract_csrf_tokens("", cookie_header="csrftoken=tok-abcdefgh"))
    headers, body = apply_csrf(
        headers={"Content-Type": "application/json"},
        body='{"title":"x"}',
        token=token,
    )
    assert headers["X-CSRF-Token"] == "tok-abcdefgh"
    assert '"csrf_token":"tok-abcdefgh"' in body


def test_apply_csrf_replaces_stale_json_token():
    token = prefer_token(extract_csrf_tokens("", cookie_header="csrftoken=fresh-tok-abcdefgh"))
    headers, body = apply_csrf(
        headers={"X-CSRF-Token": "stale"},
        body='{"csrf_token":"stale","title":"x"}',
        token=token,
    )
    assert headers["X-CSRF-Token"] == "fresh-tok-abcdefgh"
    assert '"csrf_token":"fresh-tok-abcdefgh"' in body
    assert "stale" not in body


def test_captured_write_requires_csrf():
    from shroodler.csrf import captured_write_requires_csrf, csrf_harvest_url_ok

    assert captured_write_requires_csrf('{"csrf_token":"abc"}')
    assert captured_write_requires_csrf("title=hi&csrfmiddlewaretoken=x")
    assert captured_write_requires_csrf("{}", {"X-CSRF-Token": "x"})
    assert captured_write_requires_csrf('{"title":"x"}') is False
    assert captured_write_requires_csrf('{"data":{"csrf_token":"abc"}}')
    assert captured_write_requires_csrf("{}", {"RequestVerificationToken": "x"})
    assert captured_write_requires_csrf("{}", {"Cookie": "csrftoken=abc"})
    assert not captured_write_requires_csrf('{"csrf_exempt": true}')
    assert csrf_harvest_url_ok("http://127.0.0.1/edit")
    assert not csrf_harvest_url_ok("https://example.com/edit")
    assert csrf_harvest_url_ok("https://example.com/edit", allow_external=True)
    assert not csrf_harvest_url_ok("file:///etc/passwd")
    assert not csrf_harvest_url_ok("http://user:pass@127.0.0.1/edit")
    assert not csrf_harvest_url_ok("http://")


def test_apply_csrf_form_body():
    token = prefer_token(extract_csrf_tokens("", cookie_header="csrftoken=tok-abcdefgh"))
    headers, body = apply_csrf(headers={}, body="title=hi", token=token)
    assert "csrf_token=tok-abcdefgh" in body
    assert headers["X-XSRF-TOKEN"] == "tok-abcdefgh"


def test_looks_like_csrf_rejection():
    assert looks_like_csrf_rejection(403, "Missing CSRF token")
    assert looks_like_csrf_rejection(419, '{"error":"CSRF token mismatch"}')
    assert not looks_like_csrf_rejection(200, '{"ok":true,"csrf_token":"rotated"}')
    assert not looks_like_csrf_rejection(404, "not found")


def test_apply_csrf_replaces_nested_json_and_rejects_crlf():
    token = prefer_token(extract_csrf_tokens("", cookie_header="csrftoken=fresh-tok-abcdefgh"))
    _headers, body = apply_csrf(
        headers={},
        body='{"data":{"csrf_token":"stale"},"title":"x"}',
        token=token,
    )
    assert '"csrf_token":"fresh-tok-abcdefgh"' in body
    assert "stale" not in body
    bad = token.__class__(name="csrf_token", value="abc\r\nX-Injected: 1", source="form")
    headers, body = apply_csrf(headers={}, body='{"title":"x"}', token=bad)
    assert "X-CSRF-Token" not in headers
    assert "csrf_token" not in body


def test_refresh_csrf_refuses_off_origin_and_non_local(fx):
    import httpx

    from shroodler.csrf import refresh_csrf

    fx.html("/", '<input type="hidden" name="csrf_token" value="live-tok-12345678">')
    with httpx.Client(follow_redirects=False) as http:
        assert refresh_csrf(http, "http://169.254.169.254/latest") is None
        assert (
            refresh_csrf(
                http,
                fx.origin + "/",
                same_origin_as="http://127.0.0.1:9/",
            )
            is None
        )
        token = refresh_csrf(
            http, fx.origin + "/", same_origin_as=fx.origin + "/photo/1"
        )
        assert token is not None
        assert token.value == "live-tok-12345678"


def test_csrf_finding_requires_samesite_none_and_write_form():
    page = Page(
        url="http://127.0.0.1/edit",
        status_code=200,
        forms=[
            Form(
                action="/save",
                method="POST",
                fields=[FormField(name="title", type="text", hidden=False)],
            )
        ],
        cookies=[
            Cookie(name="sessionid", secure=True, http_only=True, same_site="None"),
        ],
    )
    hits = csrf_findings([page])
    assert [f.id for f in hits] == ["csrf-state-change-unprotected"]


def test_csrf_finding_skips_lax_and_tokened_forms():
    page = Page(
        url="http://127.0.0.1/edit",
        status_code=200,
        forms=[
            Form(
                action="/save",
                method="POST",
                fields=[
                    FormField(name="title", type="text", hidden=False),
                    FormField(name="csrf_token", type="hidden", hidden=True),
                ],
            )
        ],
        cookies=[Cookie(name="sessionid", secure=True, http_only=True, same_site="Lax")],
    )
    assert csrf_findings([page]) == []


def test_confirm_csrf_origin_appends_reflected_origin(fx):
    from shroodler.extractors.csrf import confirm_csrf_origin
    from shroodler.modes.static import StaticFetcher

    page = Page(
        url=fx.origin + "/edit",
        status_code=200,
        forms=[
            Form(
                action="/save",
                method="POST",
                fields=[FormField(name="title", type="text", hidden=False)],
            )
        ],
        cookies=[
            Cookie(name="sessionid", secure=True, http_only=True, same_site="None"),
        ],
    )
    fx.on(
        "OPTIONS",
        "/save",
        lambda inc: (
            204,
            {
                "Access-Control-Allow-Origin": inc.headers.get("Origin", ""),
                "Access-Control-Allow-Methods": "POST",
            },
            b"",
        ),
    )
    hits = csrf_findings([page])
    http = StaticFetcher()
    try:
        out = confirm_csrf_origin(hits, [page], http, allow_external=False)
    finally:
        http.close()
    assert len(out) == 1
    assert "evil.example" in (out[0].evidence or "")
    assert "OPTIONS" in (out[0].evidence or "")


def test_csrf_finding_skips_javascript_and_off_origin_actions():
    page = Page(
        url="http://127.0.0.1/edit",
        status_code=200,
        forms=[
            Form(
                action="javascript:alert(1)",
                method="POST",
                fields=[FormField(name="title", type="text", hidden=False)],
            ),
            Form(
                action="https://evil.example/save",
                method="POST",
                fields=[FormField(name="title", type="text", hidden=False)],
            ),
            Form(
                action="http://user:pass@127.0.0.1/save",
                method="POST",
                fields=[FormField(name="title", type="text", hidden=False)],
            ),
        ],
        cookies=[
            Cookie(name="sessionid", secure=True, http_only=True, same_site="None"),
        ],
    )
    assert csrf_findings([page]) == []


def test_confirm_csrf_origin_is_options_only_and_per_action(fx):
    from shroodler.extractors.csrf import confirm_csrf_origin
    from shroodler.modes.static import StaticFetcher

    page = Page(
        url=fx.origin + "/edit",
        status_code=200,
        forms=[
            Form(
                action="/save",
                method="POST",
                fields=[FormField(name="title", type="text", hidden=False)],
            ),
            Form(
                action="/public",
                method="POST",
                fields=[FormField(name="title", type="text", hidden=False)],
            ),
        ],
        cookies=[
            Cookie(name="sessionid", secure=True, http_only=True, same_site="None"),
        ],
    )
    methods: list[str] = []

    def record_save(inc):
        methods.append(inc.method)
        return (204, {}, b"")

    def reflect_public(inc):
        methods.append(inc.method)
        return (
            204,
            {
                "Access-Control-Allow-Origin": inc.headers.get("Origin", ""),
                "Access-Control-Allow-Methods": "POST",
            },
            b"",
        )

    fx.on("OPTIONS", "/save", record_save)
    fx.on("GET", "/save", record_save)
    fx.on("OPTIONS", "/public", reflect_public)
    fx.on("GET", "/public", reflect_public)
    hits = csrf_findings([page])
    http = StaticFetcher()
    try:
        out = confirm_csrf_origin(hits, [page], http, allow_external=False)
    finally:
        http.close()
    assert all(m == "OPTIONS" for m in methods)
    by_url = {f.url: f for f in out}
    save = [u for u in by_url if u.endswith("/save")][0]
    public = [u for u in by_url if u.endswith("/public")][0]
    assert "evil.example" not in (by_url[save].evidence or "")
    assert "evil.example" in (by_url[public].evidence or "")


def test_csrf_finding_treats_fragment_action_as_page_url():
    page = Page(
        url="http://127.0.0.1/edit",
        status_code=200,
        forms=[
            Form(
                action="#",
                method="POST",
                fields=[FormField(name="title", type="text", hidden=False)],
            )
        ],
        cookies=[
            Cookie(name="sessionid", secure=True, http_only=True, same_site="None"),
        ],
    )
    hits = csrf_findings([page])
    assert [f.url for f in hits] == ["http://127.0.0.1/edit"]


def test_confirm_csrf_origin_strips_cookies_and_parses_acam(fx):
    from shroodler.extractors.csrf import confirm_csrf_origin
    from shroodler.modes.static import StaticFetcher

    page = Page(
        url=fx.origin + "/edit",
        status_code=200,
        forms=[
            Form(
                action="/save",
                method="PUT",
                fields=[FormField(name="title", type="text", hidden=False)],
            )
        ],
        cookies=[
            Cookie(name="sessionid", secure=True, http_only=True, same_site="None"),
        ],
    )
    seen_cookie = {"v": None}

    def handler(inc):
        seen_cookie["v"] = inc.cookies
        return (
            204,
            {
                "Access-Control-Allow-Origin": inc.headers.get("Origin", ""),
                "Access-Control-Allow-Methods": "GET, POST, COMPUTER",
            },
            b"",
        )

    fx.on("OPTIONS", "/save", handler)
    hits = csrf_findings([page])
    http = StaticFetcher()
    http.client.cookies.set("sessionid", "SECRETJAR")
    try:
        out = confirm_csrf_origin(hits, [page], http, allow_external=False)
    finally:
        http.close()
    assert seen_cookie["v"] == ""
    assert "evil.example" not in (out[0].evidence or "")
