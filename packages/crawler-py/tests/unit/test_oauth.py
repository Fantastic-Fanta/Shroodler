from __future__ import annotations

from shroodler.crawler import crawl_url
from shroodler.extractors.oauth import check_oauth_authorize_url, is_authorization_request


def _ids(findings) -> set[str]:
    return {f.id for f in findings}


def test_recognizes_authorization_request():
    assert is_authorization_request(
        "https://idp.example/authorize?response_type=code&client_id=abc&state=xyz"
    )
    assert not is_authorization_request("https://example.com/?client_id=abc")
    assert not is_authorization_request("https://example.com/?response_type=code")


def test_missing_state_is_flagged():
    findings = check_oauth_authorize_url(
        "https://idp.example/authorize?response_type=code&client_id=abc"
    )
    assert "oauth-missing-state" in _ids(findings)
    hit = next(f for f in findings if f.id == "oauth-missing-state")
    assert hit.severity == "medium"
    assert hit.category == "auth"


def test_missing_state_with_pkce_is_downgraded_to_low():
    # code_challenge (PKCE) mitigates most of the CSRF risk state
    # normally addresses -- must not be scored the same as no CSRF
    # protection at all.
    findings = check_oauth_authorize_url(
        "https://idp.example/authorize?response_type=code&client_id=abc"
        "&code_challenge=abc123&code_challenge_method=S256"
    )
    hit = next(f for f in findings if f.id == "oauth-missing-state")
    assert hit.severity == "low"
    assert "pkce" in hit.description.lower()


def test_missing_state_with_plain_pkce_stays_medium():
    # RFC 7636's "plain" method sends the verifier itself as the
    # challenge -- it doesn't hide anything in transit/logs the way S256
    # does, so it must not earn the same downgrade as a real S256
    # challenge.
    findings = check_oauth_authorize_url(
        "https://idp.example/authorize?response_type=code&client_id=abc"
        "&code_challenge=abc123&code_challenge_method=plain"
    )
    hit = next(f for f in findings if f.id == "oauth-missing-state")
    assert hit.severity == "medium"
    assert "s256" in hit.description.lower()


def test_missing_state_with_code_challenge_but_no_method_stays_medium():
    # code_challenge_method defaults to "plain" per RFC 7636 when absent
    # -- same reasoning as the explicit-plain case above.
    findings = check_oauth_authorize_url(
        "https://idp.example/authorize?response_type=code&client_id=abc&code_challenge=abc123"
    )
    hit = next(f for f in findings if f.id == "oauth-missing-state")
    assert hit.severity == "medium"


def test_hybrid_flow_response_type_is_flagged_as_implicit():
    # OIDC hybrid flow: response_type is space-separated and "token"
    # being one of several values still exposes a token in the fragment
    # -- exact string equality against the whole value would miss this.
    findings = check_oauth_authorize_url(
        "https://idp.example/authorize?response_type=code+token&client_id=abc&state=xyz"
    )
    assert "oauth-implicit-flow" in _ids(findings)


def test_hybrid_flow_code_id_token_without_bare_token_is_not_flagged():
    # "id_token" alone (no bare "token") does not itself expose an access
    # token the way response_type=token/  "...token" does.
    findings = check_oauth_authorize_url(
        "https://idp.example/authorize?response_type=code+id_token&client_id=abc&state=xyz"
    )
    assert "oauth-implicit-flow" not in _ids(findings)


def test_repeated_state_with_blank_first_value_is_flagged():
    # Regression test for a real Python/Go parity gap caught in review:
    # Python's parse_qs defaults to dropping a blank occurrence of a
    # repeated param entirely (?state=&state=real used to become just
    # {"state": ["real"]}, hiding the blank first value), while Go's
    # net/url.Values.Get returns the first value in the raw list ("").
    # Both engines must now agree: the FIRST occurrence decides, blank or
    # not, so this fires oauth-missing-state in both.
    findings = check_oauth_authorize_url(
        "https://idp.example/authorize?response_type=code&client_id=abc&state=&state=real"
    )
    assert "oauth-missing-state" in _ids(findings)


def test_empty_state_is_flagged():
    findings = check_oauth_authorize_url(
        "https://idp.example/authorize?response_type=code&client_id=abc&state="
    )
    assert "oauth-missing-state" in _ids(findings)


def test_present_state_is_not_flagged():
    findings = check_oauth_authorize_url(
        "https://idp.example/authorize?response_type=code&client_id=abc&state=xyz123"
    )
    assert "oauth-missing-state" not in _ids(findings)


def test_implicit_flow_is_flagged():
    findings = check_oauth_authorize_url(
        "https://idp.example/authorize?response_type=token&client_id=abc&state=xyz"
    )
    assert "oauth-implicit-flow" in _ids(findings)
    hit = next(f for f in findings if f.id == "oauth-implicit-flow")
    assert hit.severity == "low"


def test_code_flow_does_not_trigger_implicit_finding():
    findings = check_oauth_authorize_url(
        "https://idp.example/authorize?response_type=code&client_id=abc&state=xyz"
    )
    assert "oauth-implicit-flow" not in _ids(findings)


def test_non_authorize_url_is_ignored():
    assert check_oauth_authorize_url("https://example.com/search?q=hello") == []


def test_crawl_flags_oauth_authorize_link(fx):
    fx.html(
        "/",
        '<html><body><a href="/authorize?response_type=code&client_id=abc">login</a></body></html>',
    )
    fx.html("/authorize", "<html><body>authorize</body></html>")
    result = crawl_url(fx.origin + "/", depth=1)
    ids = {f.id for f in result.findings}
    assert "oauth-missing-state" in ids
