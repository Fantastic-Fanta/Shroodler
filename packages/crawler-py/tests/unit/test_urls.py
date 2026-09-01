from __future__ import annotations

from shroodler.urls import canonical_key, is_loopback_or_local, normalize_url, same_origin


def test_canonical_trailing_slash_and_query_order():
    a = canonical_key("http://127.0.0.1:8081/dup/")
    b = canonical_key("http://127.0.0.1:8081/dup")
    assert a == b
    c = canonical_key("http://127.0.0.1:8081/dup?b=2&a=1")
    d = canonical_key("http://127.0.0.1:8081/dup?a=1&b=2")
    assert c == d
    e = canonical_key("http://127.0.0.1:8081/dup#frag")
    f = canonical_key("http://127.0.0.1:8081/dup")
    assert e == f


def test_same_origin_and_local():
    assert same_origin("http://127.0.0.1:8081/a", "http://127.0.0.1:8081/b")
    assert not same_origin("http://127.0.0.1:8081/a", "http://127.0.0.1:8082/a")
    assert is_loopback_or_local("http://localhost:8081/")
    assert is_loopback_or_local("http://app1.local:8081/")
    assert not is_loopback_or_local("http://example.com/")


def test_normalize_rejects_javascript():
    assert normalize_url("http://127.0.0.1/", "javascript:alert(1)") is None
    assert normalize_url("http://127.0.0.1/dir/", "../x") == "http://127.0.0.1/x"
