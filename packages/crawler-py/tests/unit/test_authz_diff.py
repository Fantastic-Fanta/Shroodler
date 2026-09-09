from __future__ import annotations

import pytest

from shroodler.authz_diff import headers_from_auth_line, run


def _doc(origin: str, urls: list[str]) -> dict:
    return {"target": origin + "/", "pages": [{"url": u} for u in urls]}


def test_refuses_external_without_allow_external():
    with pytest.raises(ValueError, match="non-local"):
        run({"target": "https://example.com/", "pages": []})


def test_allow_external_bypasses_guard():
    out = run({"target": "https://example.com/", "pages": []}, allow_external=True)
    assert out == {"target": "https://example.com/", "findings": []}


def test_enforcer_blocks_before_any_request(fx):
    from shroodler_guardrails.policy import PolicyEnforcer, origin_of, parse_policy

    calls = []
    fx.on("GET", "/admin/report/1", lambda inc: calls.append(1) or (200, {}, b"secret"))
    policy = parse_policy({"allow": ["/nope/*"]}, origin=origin_of(fx.origin))
    enforcer = PolicyEnforcer(policy=policy)
    doc = _doc(fx.origin, [fx.origin + "/admin/report/1"])
    out = run(doc, cookie_header="session=x", enforcer=enforcer)
    assert out["findings"] == []
    assert not calls, "enforcer should block the request before it's ever sent"
    assert enforcer.summary()["requests_blocked"] >= 1


def test_enforcer_allows_and_counts_both_lower_and_anon_requests(fx):
    from shroodler_guardrails.policy import PolicyEnforcer, origin_of, parse_policy

    fx.on(
        "GET",
        "/admin/report/1",
        lambda inc: (200, {}, b"secret") if "session=x" in inc.cookies else (403, {}, b"no"),
    )
    policy = parse_policy({"allow": ["*"]}, origin=origin_of(fx.origin))
    enforcer = PolicyEnforcer(policy=policy)
    doc = _doc(fx.origin, [fx.origin + "/admin/report/1"])
    out = run(doc, cookie_header="session=x", enforcer=enforcer)
    assert {f["id"] for f in out["findings"]} == {"authz-broken-access-control"}
    # One lower-priv request + one anonymous control request == 2 checks.
    assert enforcer.summary()["requests_attempted"] == 2


def test_flags_broken_access_control_when_anon_denied(fx):
    fx.on(
        "GET",
        "/admin/report/1",
        lambda inc: (200, {}, b"secret report")
        if "session=admin-or-user" in inc.cookies
        else (403, {}, b"forbidden"),
    )
    doc = _doc(fx.origin, [fx.origin + "/admin/report/1"])
    out = run(doc, cookie_header="session=admin-or-user")
    ids = {f["id"] for f in out["findings"]}
    assert "authz-broken-access-control" in ids
    assert out["findings"][0]["confidence"] == "confirmed"


def test_identity_marker_upgrades_confidence_to_confirmed(fx):
    fx.on(
        "GET",
        "/admin/report/1",
        lambda inc: (200, {}, b'{"owner_email": "victim@example.com", "data": "secret"}')
        if "session=x" in inc.cookies
        else (403, {}, b"no"),
    )
    doc = _doc(fx.origin, [fx.origin + "/admin/report/1"])
    out = run(
        doc,
        cookie_header="session=x",
        higher_priv_identity_markers=["victim@example.com"],
    )
    finding = out["findings"][0]
    assert finding["id"] == "authz-broken-access-control"
    assert finding["confidence"] == "confirmed"
    assert "victim@example.com" in finding["description"]


def test_marker_never_confirms_when_anon_check_disabled(fx):
    # Without an anonymous control response to cross-check against, a
    # marker must never confirm a lead -- even a genuinely unique one --
    # so results stay reproducible regardless of whether check_anonymous
    # happens to run on a given call.
    fx.on(
        "GET",
        "/admin/report/1",
        lambda inc: (200, {}, b'{"owner_email": "victim@example.com"}'),
    )
    doc = _doc(fx.origin, [fx.origin + "/admin/report/1"])
    out = run(
        doc,
        cookie_header="session=x",
        check_anonymous=False,
        higher_priv_identity_markers=["victim@example.com"],
    )
    finding = out["findings"][0]
    assert finding["id"] == "authz-still-accessible"
    assert "confidence" not in finding


def test_short_degenerate_marker_is_ignored(fx):
    # A short/common marker ("admin") would coincidentally match almost
    # any page -- must not silently upgrade every lead to "confirmed".
    fx.on(
        "GET",
        "/admin/report/1",
        lambda inc: (200, {}, b"welcome, admin panel")
        if "session=x" in inc.cookies
        else (403, {}, b"no"),
    )
    doc = _doc(fx.origin, [fx.origin + "/admin/report/1"])
    out = run(
        doc,
        cookie_header="session=x",
        higher_priv_identity_markers=["admin"],
    )
    finding = out["findings"][0]
    assert finding["id"] == "authz-broken-access-control"
    # Short markers must not add identity-confirmation text, but peer=200 /
    # anon-denied is still enough to stamp confidence=confirmed.
    assert finding["confidence"] == "confirmed"
    assert "identity marker" not in finding["description"]


def test_marker_present_in_anonymous_response_is_not_confirmation(fx):
    # A long-enough marker that's also visible to an anonymous visitor
    # (page boilerplate: a footer, a repeated nav fragment) can't be
    # evidence of a specific account's private data, regardless of its
    # length -- must not upgrade to confidence=confirmed.
    def handler(inc):
        if "session=x" in inc.cookies:
            return (200, {}, b"boilerplate-footer-text and some secret data")
        # Neither denied (401/403) nor success -- falls through to the
        # authz-still-accessible path, where anon_resp is still fetched.
        return (500, {}, b"boilerplate-footer-text on the error page too")

    fx.on("GET", "/report/1", handler)
    doc = _doc(fx.origin, [fx.origin + "/report/1"])
    out = run(
        doc,
        cookie_header="session=x",
        higher_priv_identity_markers=["boilerplate-footer-text"],
    )
    finding = out["findings"][0]
    assert finding["id"] == "authz-still-accessible"
    assert "confidence" not in finding


def test_broken_access_control_is_confirmed_without_markers(fx):
    fx.on(
        "GET",
        "/admin/report/1",
        lambda inc: (200, {}, b"generic content")
        if "session=x" in inc.cookies
        else (403, {}, b"no"),
    )
    doc = _doc(fx.origin, [fx.origin + "/admin/report/1"])
    out = run(
        doc,
        cookie_header="session=x",
        higher_priv_identity_markers=["victim@example.com"],
    )
    finding = out["findings"][0]
    assert finding["id"] == "authz-broken-access-control"
    assert finding["confidence"] == "confirmed"


def test_require_identity_confirmation_drops_unconfirmed_lead(fx):
    fx.on(
        "GET",
        "/admin/report/1",
        lambda inc: (200, {}, b"generic content, no identity markers here")
        if "session=x" in inc.cookies
        else (403, {}, b"no"),
    )
    doc = _doc(fx.origin, [fx.origin + "/admin/report/1"])
    out = run(
        doc,
        cookie_header="session=x",
        higher_priv_identity_markers=["victim@example.com"],
        require_identity_confirmation=True,
    )
    assert out["findings"] == []


def test_lower_priv_own_marker_does_not_count_as_confirmation(fx):
    # If the "higher-priv" marker happens to equal something the LOWER-
    # priv account also legitimately sees (e.g. a shared placeholder),
    # it must not count as confirmation of cross-account leakage.
    fx.on(
        "GET",
        "/admin/report/1",
        lambda inc: (200, {}, b"shared@example.com")
        if "session=x" in inc.cookies
        else (403, {}, b"no"),
    )
    doc = _doc(fx.origin, [fx.origin + "/admin/report/1"])
    out = run(
        doc,
        cookie_header="session=x",
        higher_priv_identity_markers=["shared@example.com"],
        lower_priv_identity_markers=["shared@example.com"],
        require_identity_confirmation=True,
    )
    assert out["findings"] == []


def test_no_finding_when_anon_also_allowed(fx):
    fx.on("GET", "/public/page", lambda inc: (200, {}, b"public"))
    doc = _doc(fx.origin, [fx.origin + "/public/page"])
    out = run(doc, cookie_header="session=whatever")
    assert out["findings"] == []


def test_no_finding_when_lower_priv_denied(fx):
    fx.on(
        "GET",
        "/admin/only",
        lambda inc: (200, {}, b"secret")
        if "session=real-admin" in inc.cookies
        else (403, {}, b"nope"),
    )
    doc = _doc(fx.origin, [fx.origin + "/admin/only"])
    out = run(doc, cookie_header="session=not-admin")
    assert out["findings"] == []


def test_no_anon_check_reports_any_reachable_url(fx):
    fx.on("GET", "/somewhere", lambda inc: (200, {}, b"ok"))
    doc = _doc(fx.origin, [fx.origin + "/somewhere"])
    out = run(doc, cookie_header="session=x", check_anonymous=False)
    ids = {f["id"] for f in out["findings"]}
    assert "authz-still-accessible" in ids


def test_dedupes_repeated_urls(fx):
    fx.on("GET", "/dup", lambda inc: (200, {}, b"ok"))
    doc = _doc(fx.origin, [fx.origin + "/dup", fx.origin + "/dup"])
    out = run(doc, cookie_header="session=x", check_anonymous=False)
    assert len(out["findings"]) == 1


def test_login_redirect_counts_as_denied(fx):
    fx.on(
        "GET",
        "/account",
        lambda inc: (200, {}, b"account page")
        if "session=admin-or-user" in inc.cookies
        else (302, {"Location": "/login"}, b""),
    )
    doc = _doc(fx.origin, [fx.origin + "/account"])
    out = run(doc, cookie_header="session=admin-or-user")
    ids = {f["id"] for f in out["findings"]}
    assert "authz-broken-access-control" in ids


def test_ordinary_redirect_is_not_treated_as_denied(fx):
    # A ubiquitous trailing-slash-style redirect that has nothing to do
    # with authorization must not be mistaken for an access-control wall --
    # it should fall through to the weaker "verify manually" signal rather
    # than the high-severity broken-access-control finding.
    fx.on(
        "GET",
        "/reports",
        lambda inc: (200, {}, b"report list")
        if "session=admin-or-user" in inc.cookies
        else (302, {"Location": "/reports/"}, b""),
    )
    doc = _doc(fx.origin, [fx.origin + "/reports"])
    out = run(doc, cookie_header="session=admin-or-user")
    ids = {f["id"] for f in out["findings"]}
    assert "authz-broken-access-control" not in ids
    assert "authz-still-accessible" in ids


def test_replays_supplied_graphql_fields_when_introspection_blocked(fx):
    import json

    def handle(inc):
        query = ""
        if inc.body:
            query = str(json.loads(inc.body.decode()).get("query") or "")
        if "__type" in query:
            return 200, {"Content-Type": "application/json"}, b'{"errors":[{"message":"no"}]}'
        if "wallet" in query:
            if "session=user" in inc.cookies:
                return 200, {"Content-Type": "application/json"}, b'{"data":{"wallet":{"id":1}}}'
            return 200, {"Content-Type": "application/json"}, b'{"errors":[{"message":"no"}]}'
        return 200, {"Content-Type": "application/json"}, b'{"data":{"__typename":"Query"}}'

    fx.on("POST", "/graphql", handle)
    fx.on("GET", "/graphql", lambda inc: (200, {}, b'{"data":{"__typename":"Query"}}'))
    doc = {
        "target": fx.origin + "/",
        "pages": [{"url": fx.origin + "/graphql"}],
        "js_endpoints": [{"source": fx.origin + "/graphql", "endpoint": "graphql-field:wallet"}],
    }
    out = run(doc, cookie_header="session=user")
    assert any(f["id"] == "graphql-field-authz" for f in out["findings"])


def test_headers_from_auth_line_authorization_and_cookie():
    assert headers_from_auth_line("Authorization: Bearer api-xxx") == {
        "Authorization": "Bearer api-xxx"
    }
    assert headers_from_auth_line("Cookie: session=x") == {"Cookie": "session=x"}
    assert headers_from_auth_line("session=x") == {"Cookie": "session=x"}
    assert headers_from_auth_line("") == {}
    assert headers_from_auth_line(None) == {}


def test_authorization_header_is_sent_not_cookie(fx):
    seen = []

    def handle(inc):
        seen.append(inc.headers)
        if inc.headers.get("Authorization") == "Bearer tok":
            return 200, {}, b"secret"
        return 403, {}, b"no"

    fx.on("GET", "/admin/report/1", handle)
    doc = _doc(fx.origin, [fx.origin + "/admin/report/1"])
    out = run(doc, cookie_header="Authorization: Bearer tok")
    assert seen
    assert seen[0].get("Authorization") == "Bearer tok"
    assert "Cookie" not in seen[0] or "Bearer tok" not in seen[0].get("Cookie", "")
    assert {f["id"] for f in out["findings"]} == {"authz-broken-access-control"}


def test_higher_cookie_header_fetches_owner_baseline(fx):
    roles = []

    def handle(inc):
        auth = inc.headers.get("Authorization", "")
        roles.append(auth)
        if auth == "Bearer owner":
            return 200, {}, b"owner-secret-report-data"
        if auth == "Bearer peer":
            return 200, {}, b"owner-secret-report-data"
        return 403, {}, b"no"

    fx.on("GET", "/admin/report/1", handle)
    doc = _doc(fx.origin, [fx.origin + "/admin/report/1"])
    out = run(
        doc,
        cookie_header="Authorization: Bearer peer",
        higher_cookie_header="Authorization: Bearer owner",
    )
    assert "Bearer owner" in roles
    assert "Bearer peer" in roles
    assert out["findings"]


def test_post_form_replay_flags_broken_access_control(fx):
    def handle(inc):
        if inc.method != "POST":
            return 405, {}, b"no"
        if "session=user" in inc.cookies:
            return 200, {}, b'{"lessonCompleted":false}'
        return 302, {"Location": "/login"}, b""

    fx.on("POST", "/access-control/hidden-menu", handle)
    fx.on("GET", "/access-control/hidden-menu", handle)
    doc = {
        "target": fx.origin + "/",
        "pages": [
            {
                "url": fx.origin + "/access-control/hidden-menu",
                "method": "POST",
                "params": [
                    {"name": "hiddenMenu1"},
                    {"name": "hiddenMenu2"},
                    {"name": "submit"},
                ],
            }
        ],
    }
    out = run(doc, cookie_header="session=user")
    finding = out["findings"][0]
    assert finding["id"] == "authz-broken-access-control"
    assert finding["confidence"] == "confirmed"
