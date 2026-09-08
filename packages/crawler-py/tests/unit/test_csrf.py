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


def test_apply_csrf_form_body():
    token = prefer_token(extract_csrf_tokens("", cookie_header="csrftoken=tok-abcdefgh"))
    headers, body = apply_csrf(headers={}, body="title=hi", token=token)
    assert "csrf_token=tok-abcdefgh" in body
    assert headers["X-XSRF-TOKEN"] == "tok-abcdefgh"


def test_looks_like_csrf_rejection():
    assert looks_like_csrf_rejection(403, "Missing CSRF token")
    assert looks_like_csrf_rejection(200, '{"error":"CSRF token mismatch"}')
    assert not looks_like_csrf_rejection(404, "not found")


def test_refresh_csrf_from_httpx_like(fx):
    fx.html(
        "/",
        '<input type="hidden" name="csrf_token" value="live-tok-12345678">',
    )
    import httpx

    with httpx.Client() as http:
        token = refresh_csrf(http, fx.origin + "/")
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
