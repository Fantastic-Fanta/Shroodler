from __future__ import annotations

import json

from shroodler.pacer import Pacer
from shroodler.program import load
from shroodler.rest_crawler import (
    crawl_rest,
    extract_rest_urls,
    merge_rest_into_state,
)


class FakeResp:
    def __init__(self, status=200, text="", headers=None, url=""):
        self.status_code = status
        self.text = text
        self.content = text.encode() if isinstance(text, str) else text
        self.headers = headers or {"content-type": "application/json"}
        self.url = url


class FakeClient:
    def __init__(self, routes: dict[str, FakeResp]):
        self.routes = routes
        self.calls: list[tuple[str, dict]] = []

    def request(self, method, url, **kw):
        self.calls.append((url, kw.get("headers") or {}))
        from urllib.parse import urlparse

        path = urlparse(url).path
        resp = self.routes.get(path) or self.routes.get(url)
        if resp is None:
            return FakeResp(404, "{}", url=url)
        if not resp.url:
            resp.url = url
        return resp

    def close(self):
        pass


def test_extract_rest_urls_relative_absolute_and_hateoas():
    data = {
        "accountId": "800002",
        "self": "/api/account/800002",
        "url": "/api/profile",
        "uri": "/api/settings",
        "abs": "http://127.0.0.1/api/abs",
        "off": "https://evil.example/api/x",
        "_links": {"next": {"href": "/api/account/800003"}},
        "links": [{"href": "/api/account/800004"}],
        "href": "/api/me",
    }
    urls = extract_rest_urls("http://127.0.0.1/api/account/800002", data)
    paths = {u.split("http://127.0.0.1")[-1] for u in urls}
    assert "/api/account/800002" in paths
    assert "/api/profile" in paths
    assert "/api/settings" in paths
    assert "/api/abs" in paths
    assert "/api/account/800003" in paths
    assert "/api/account/800004" in paths
    assert "/api/me" in paths
    assert not any("evil.example" in u for u in urls)


def test_crawl_rest_extracts_ids_and_follows_json():
    client = FakeClient(
        {
            "/api": FakeResp(
                200,
                json.dumps(
                    {
                        "accountId": "800002",
                        "next": "/api/account/800002",
                        "_links": {"self": {"href": "/api/account/800002"}},
                    }
                ),
            ),
            "/api/account/800002": FakeResp(
                200,
                json.dumps({"accountId": "800002", "user_id": "99", "balance": 12}),
            ),
        }
    )
    result = crawl_rest(
        "http://127.0.0.1/api",
        client=client,
        pacer=Pacer(0),
        max_pages=10,
    )
    paths = {p["url"].rstrip("/") for p in result.pages}
    assert "http://127.0.0.1/api" in paths
    assert "http://127.0.0.1/api/account/800002" in paths
    flat_ids = [oid for ids in result.object_ids.values() for oid in ids]
    assert "800002" in flat_ids
    assert "99" in flat_ids
    assert all(ep["source"] == "rest-crawl" for ep in result.endpoints)


def test_crawl_rest_skips_html_and_off_origin():
    client = FakeClient(
        {
            "/api": FakeResp(
                200,
                json.dumps({"next": "https://evil.example/secret", "page": "/index.html"}),
            ),
            "/index.html": FakeResp(
                200,
                "<html><a href='/secret'>x</a></html>",
                headers={"content-type": "text/html"},
            ),
        }
    )
    result = crawl_rest(
        "http://127.0.0.1/api",
        client=client,
        pacer=Pacer(0),
    )
    assert len(result.pages) == 1
    assert not any("evil.example" in u for u, _ in client.calls)


def test_crawl_rest_attaches_bearer_and_stores_discovered_token():
    client = FakeClient(
        {
            "/login": FakeResp(
                200,
                json.dumps({"access_token": "tok-from-login", "next": "/api/me"}),
            ),
            "/api/me": FakeResp(200, json.dumps({"id": 7})),
        }
    )
    result = crawl_rest(
        "http://127.0.0.1/login",
        bearer_token="seed-token",
        client=client,
        pacer=Pacer(0),
    )
    first_headers = client.calls[0][1]
    assert first_headers.get("Authorization") == "Bearer seed-token"
    assert result.bearer_token == "seed-token"
    # Seed already present — do not replace with the login body token.
    assert result.bearer_token != "tok-from-login"

    client2 = FakeClient(
        {
            "/login": FakeResp(
                200,
                json.dumps({"access_token": "tok-from-login", "url": "/api/me"}),
            ),
            "/api/me": FakeResp(200, json.dumps({"id": 7})),
        }
    )
    discovered = crawl_rest(
        "http://127.0.0.1/login",
        client=client2,
        pacer=Pacer(0),
    )
    assert discovered.bearer_token == "tok-from-login"
    me_headers = [h for u, h in client2.calls if u.endswith("/api/me")]
    assert me_headers
    assert me_headers[0].get("Authorization") == "Bearer tok-from-login"


def test_crawl_rest_does_not_invent_tokens():
    client = FakeClient({"/api": FakeResp(200, json.dumps({"ok": True}))})
    result = crawl_rest("http://127.0.0.1/api", client=client, pacer=Pacer(0))
    assert result.bearer_token == ""
    assert "Authorization" not in client.calls[0][1]


def test_merge_rest_into_state(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    client = FakeClient(
        {
            "/api/account/800002": FakeResp(
                200,
                json.dumps({"accountId": "800002", "note": "hi", "href": "/api/me"}),
            ),
            "/api/me": FakeResp(200, json.dumps({"id": 1})),
        }
    )
    result = crawl_rest(
        "http://127.0.0.1/api/account/800002",
        bearer_token="abc",
        client=client,
        pacer=Pacer(0),
    )
    state = load("lab")
    delta = merge_rest_into_state(state, result)
    assert delta["new_endpoints"] >= 1
    acct = "http://127.0.0.1/api/account/800002"
    assert state.endpoints[acct]["source"] == "rest-crawl"
    names = {p["name"] for p in state.endpoints[acct]["params"]}
    assert "accountId" in names
    assert "note" in names
    pattern = "/api/account/{id}"
    assert "800002" in state.object_ids.get(pattern, [])
    assert state.bearer_token == "abc"
