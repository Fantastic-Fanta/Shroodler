from __future__ import annotations


def test_auth0_in_query_is_not_a_fingerprint():
    from types import SimpleNamespace

    from shroodler.extractors.auth_stack import _has_auth0

    page = SimpleNamespace(url="http://127.0.0.1/?next=https://auth0.com/login", cookies=[])
    assert not _has_auth0([], [page])


def test_keycloak_authorize_uses_origin_not_seed_path():
    from types import SimpleNamespace

    from shroodler.extractors.auth_stack import probe_redirect_uri_allowlist

    seen: list[str] = []

    class _Http:
        def request(self, method, url, anonymous=False):
            seen.append(url)
            return SimpleNamespace(status_code=400, text="", headers={}, redirect_to=None)

    page = SimpleNamespace(url="http://127.0.0.1/app/realms/app/account", cookies=[])
    probe_redirect_uri_allowlist(
        "http://127.0.0.1/app/",
        _Http(),
        [page],
        keycloak=True,
        allow_external=True,
    )
    assert seen
    assert all("/app/realms/" not in u for u in seen)
    assert any("/realms/app/protocol/openid-connect/auth" in u for u in seen)
