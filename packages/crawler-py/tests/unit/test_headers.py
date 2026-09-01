from __future__ import annotations

from shroodler.extractors.headers import extract_headers


def test_csp_strict_weak_absent():
    _, f_strict = extract_headers(
        {"Content-Security-Policy": "default-src 'self'"},
        "https://127.0.0.1/",
    )
    assert all(x.id != "missing-csp" and x.id != "weak-csp" for x in f_strict)

    _, f_weak = extract_headers(
        {"Content-Security-Policy": "default-src 'self' 'unsafe-inline'"},
        "https://127.0.0.1/",
    )
    assert any(x.id == "weak-csp" for x in f_weak)

    analysis, f_abs = extract_headers({}, "https://127.0.0.1/")
    assert "Content-Security-Policy" in analysis.missing
    assert any(x.id == "missing-csp" for x in f_abs)


def test_x_frame_options_states():
    _, f_deny = extract_headers({"X-Frame-Options": "DENY"}, "https://127.0.0.1/")
    assert all(x.id != "missing-x-frame-options" for x in f_deny)
    _, f_so = extract_headers({"X-Frame-Options": "SAMEORIGIN"}, "https://127.0.0.1/")
    assert all(x.id != "missing-x-frame-options" for x in f_so)
    _, f_abs = extract_headers({}, "https://127.0.0.1/")
    assert any(x.id == "missing-x-frame-options" for x in f_abs)


def test_hsts_present_absent_short():
    _, f_ok = extract_headers(
        {"Strict-Transport-Security": "max-age=31536000"},
        "https://127.0.0.1/",
    )
    assert all(x.id not in {"missing-hsts", "short-hsts"} for x in f_ok)
    _, f_short = extract_headers(
        {"Strict-Transport-Security": "max-age=60"},
        "https://127.0.0.1/",
    )
    assert any(x.id == "short-hsts" for x in f_short)
    _, f_abs = extract_headers({}, "https://127.0.0.1/")
    assert any(x.id == "missing-hsts" for x in f_abs)
    _, f_http = extract_headers({}, "http://127.0.0.1/")
    assert all(x.id != "missing-hsts" for x in f_http)


def test_x_content_type_options():
    _, f_ok = extract_headers({"X-Content-Type-Options": "nosniff"}, "http://127.0.0.1/")
    assert all(x.id != "missing-x-content-type-options" for x in f_ok)
    _, f_abs = extract_headers({}, "http://127.0.0.1/")
    assert any(x.id == "missing-x-content-type-options" for x in f_abs)


def test_referrer_policy():
    _, f_ok = extract_headers({"Referrer-Policy": "no-referrer"}, "http://127.0.0.1/")
    assert all(x.id != "missing-referrer-policy" for x in f_ok)
    _, f_abs = extract_headers({}, "http://127.0.0.1/")
    assert any(x.id == "missing-referrer-policy" for x in f_abs)


def test_server_and_x_powered_by():
    _, f_leak = extract_headers(
        {"Server": "Werkzeug/3.0.3 Python/3.12", "X-Powered-By": "Flask/3.0.3"},
        "http://127.0.0.1/",
    )
    assert any(x.id == "server-version-leak" for x in f_leak)
    assert any(x.id == "x-powered-by" for x in f_leak)
    _, f_abs = extract_headers({}, "http://127.0.0.1/")
    assert all(x.id not in {"server-version-leak", "x-powered-by"} for x in f_abs)
