from __future__ import annotations

import pytest

from shroodler.extractors.cookies import extract_cookies, parse_set_cookie


@pytest.mark.parametrize("secure", [True, False])
@pytest.mark.parametrize("http_only", [True, False])
@pytest.mark.parametrize("same_site", ["Strict", "Lax", "None"])
def test_cookie_flag_matrix(secure: bool, http_only: bool, same_site: str):
    parts = ["sid=abc"]
    if secure:
        parts.append("Secure")
    if http_only:
        parts.append("HttpOnly")
    parts.append(f"SameSite={same_site}")
    raw = "; ".join(parts)
    cookie = parse_set_cookie(raw)
    assert cookie is not None
    assert cookie.secure is secure
    assert cookie.http_only is http_only
    assert cookie.same_site == same_site
    cookies, findings = extract_cookies([raw], "http://127.0.0.1/dash")
    assert cookies[0].name == "sid"
    ids = {f.id for f in findings}
    if not secure:
        assert "insecure-cookie" in ids
    else:
        assert "insecure-cookie" not in ids
    if not http_only:
        assert "cookie-not-httponly" in ids
    else:
        assert "cookie-not-httponly" not in ids
    if same_site == "None" and not secure:
        assert "cookie-samesite-none-without-secure" in ids


@pytest.mark.parametrize("secure", [True, False])
@pytest.mark.parametrize("http_only", [True, False])
def test_cookie_samesite_absent(secure: bool, http_only: bool):
    parts = ["guest=1"]
    if secure:
        parts.append("Secure")
    if http_only:
        parts.append("HttpOnly")
    cookie = parse_set_cookie("; ".join(parts))
    assert cookie is not None
    assert cookie.same_site is None
    assert cookie.secure is secure
    assert cookie.http_only is http_only


def _ids(headers: list[str], url: str) -> set[str]:
    _, findings = extract_cookies(headers, url)
    return {f.id for f in findings}


def test_cookie_path_broad_on_session_root_path():
    ids = _ids(
        ["session_id=abc; Path=/; HttpOnly; SameSite=Lax"],
        "http://127.0.0.1/dashboard",
    )
    assert "cookie-path-broad" in ids
    assert "insecure-cookie" in ids


def test_cookie_path_broad_not_on_restricted_or_non_session():
    restricted = _ids(
        ["session_id=abc; Path=/account; HttpOnly; SameSite=Lax"],
        "http://127.0.0.1/account",
    )
    assert "cookie-path-broad" not in restricted
    omitted = _ids(
        ["session_id=abc; HttpOnly; SameSite=Lax"],
        "http://127.0.0.1/dashboard",
    )
    assert "cookie-path-broad" not in omitted
    prefs = _ids(
        ["prefs=1; Path=/; HttpOnly; SameSite=Lax"],
        "http://127.0.0.1/dashboard",
    )
    assert "cookie-path-broad" not in prefs


def test_cookie_domain_broad_loopback_and_parent():
    loopback = _ids(
        ["prefs=1; Path=/; Domain=example.com; HttpOnly; SameSite=Lax"],
        "http://127.0.0.1/dashboard",
    )
    assert "cookie-domain-broad" in loopback
    parent = _ids(
        ["sid=1; Path=/; Domain=example.com; Secure; HttpOnly; SameSite=Lax"],
        "https://app.example.com/dash",
    )
    assert "cookie-domain-broad" in parent


def test_cookie_domain_broad_false_positives():
    host_only = _ids(
        ["session_id=abc; Path=/; HttpOnly; SameSite=Lax"],
        "http://127.0.0.1/dashboard",
    )
    assert "cookie-domain-broad" not in host_only
    exact = _ids(
        ["sid=1; Domain=app.example.com; Secure; HttpOnly; SameSite=Lax"],
        "https://app.example.com/dash",
    )
    assert "cookie-domain-broad" not in exact
    sibling = _ids(
        ["sid=1; Domain=other.com; Secure; HttpOnly; SameSite=Lax"],
        "https://app.example.com/dash",
    )
    assert "cookie-domain-broad" not in sibling


def test_cookie_missing_host_prefix_https_session():
    ids = _ids(
        ["session_id=abc; Path=/; Secure; HttpOnly; SameSite=Strict"],
        "https://app.example.com/dash",
    )
    assert "cookie-missing-host-prefix" in ids
    assert "cookie-missing-secure-prefix" not in ids
    assert "cookie-path-broad" in ids


def test_cookie_missing_secure_prefix_when_host_prefix_inapplicable():
    with_domain = _ids(
        ["session_id=abc; Path=/; Domain=app.example.com; Secure; HttpOnly; SameSite=Lax"],
        "https://app.example.com/dash",
    )
    assert "cookie-missing-secure-prefix" in with_domain
    assert "cookie-missing-host-prefix" not in with_domain
    nested_path = _ids(
        ["session_id=abc; Path=/account; Secure; HttpOnly; SameSite=Lax"],
        "https://app.example.com/account",
    )
    assert "cookie-missing-secure-prefix" in nested_path
    assert "cookie-missing-host-prefix" not in nested_path


def test_cookie_prefix_false_positives():
    already_host = _ids(
        ["__Host-session_id=abc; Path=/; Secure; HttpOnly; SameSite=Strict"],
        "https://app.example.com/dash",
    )
    assert "cookie-missing-host-prefix" not in already_host
    assert "cookie-missing-secure-prefix" not in already_host
    already_secure = _ids(
        ["__Secure-session_id=abc; Path=/account; Secure; HttpOnly; SameSite=Lax"],
        "https://app.example.com/account",
    )
    assert "cookie-missing-secure-prefix" not in already_secure
    http_local = _ids(
        ["session_id=abc; Path=/; HttpOnly; SameSite=Lax"],
        "http://127.0.0.1/dashboard",
    )
    assert "cookie-missing-host-prefix" not in http_local
    assert "cookie-missing-secure-prefix" not in http_local
    no_secure = _ids(
        ["session_id=abc; Path=/; HttpOnly; SameSite=Lax"],
        "https://app.example.com/dash",
    )
    assert "cookie-missing-host-prefix" not in no_secure
    assert "cookie-missing-secure-prefix" not in no_secure
    prefs = _ids(
        ["prefs=1; Path=/; Secure; HttpOnly; SameSite=Lax"],
        "https://app.example.com/dash",
    )
    assert "cookie-missing-host-prefix" not in prefs
    assert "cookie-missing-secure-prefix" not in prefs


def test_cookie_secure_prefix_violation():
    ids = _ids(["__Secure-id=abc; Path=/"], "https://app.example.com/")
    assert "cookie-secure-prefix-violation" in ids


def test_cookie_secure_prefix_with_secure_is_clean():
    ids = _ids(["__Secure-id=abc; Path=/; Secure"], "https://app.example.com/")
    assert "cookie-secure-prefix-violation" not in ids


def test_cookie_host_prefix_violation_missing_secure():
    ids = _ids(["__Host-id=abc; Path=/"], "https://app.example.com/")
    assert "cookie-host-prefix-violation" in ids


def test_cookie_host_prefix_violation_has_domain():
    ids = _ids(
        ["__Host-id=abc; Path=/; Secure; Domain=example.com"],
        "https://app.example.com/",
    )
    assert "cookie-host-prefix-violation" in ids


def test_cookie_host_prefix_violation_wrong_path():
    ids = _ids(
        ["__Host-id=abc; Path=/account; Secure"],
        "https://app.example.com/account",
    )
    assert "cookie-host-prefix-violation" in ids


def test_cookie_host_prefix_violation_missing_path():
    # __Host- requires an EXPLICIT Path=/ -- omitting Path entirely is
    # itself a violation, not a safe default.
    ids = _ids(["__Host-id=abc; Secure"], "https://app.example.com/")
    assert "cookie-host-prefix-violation" in ids


def test_cookie_host_prefix_compliant_is_clean():
    ids = _ids(["__Host-id=abc; Path=/; Secure"], "https://app.example.com/")
    assert "cookie-host-prefix-violation" not in ids


def test_cookie_prefix_violation_applies_regardless_of_session_name_heuristic():
    # The prefix contract is enforced by the browser for ANY cookie name
    # carrying the prefix, not just ones this tool's is_session_cookie()
    # heuristic happens to recognize.
    ids = _ids(["__Host-not_a_session_name=abc; Path=/account; Secure"], "https://app.example.com/account")
    assert "cookie-host-prefix-violation" in ids
