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
