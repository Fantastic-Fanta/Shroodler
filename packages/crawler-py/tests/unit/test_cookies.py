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
