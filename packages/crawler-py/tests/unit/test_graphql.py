from __future__ import annotations

import json
from urllib.parse import urlparse

from shroodler.crawler import crawl_url
from shroodler.extractors.graphql import (
    format_types,
    looks_like_graphql,
    parse_schema_types,
    probe_graphql,
)


def _paths(result) -> set[str]:
    return {urlparse(p.url).path for p in result.pages}


def test_looks_like_graphql_typename():
    assert looks_like_graphql('{"data":{"__typename":"Query"}}')
    assert looks_like_graphql('{"errors":[{"message":"syntax"}]}')


def test_looks_like_graphql_rejects_non_graphql():
    assert not looks_like_graphql("")
    assert not looks_like_graphql("not json")
    assert not looks_like_graphql('{"ok":true}')
    assert not looks_like_graphql('{"data":{"users":[]}}')
    assert not looks_like_graphql('{"data":["x"]}')
    assert not looks_like_graphql('{"errors":"nope"}')
    assert not looks_like_graphql('{"errors":[{"code":1}]}')


def test_parse_schema_types_and_truncate():
    body = json.dumps(
        {
            "data": {
                "__schema": {
                    "types": [
                        {"name": "Query"},
                        {"name": "HiddenNote"},
                        {"name": "Query"},
                        {"name": 1},
                        {"name": "String"},
                    ]
                }
            }
        }
    )
    names = parse_schema_types(body)
    assert names == ["Query", "HiddenNote", "String"]
    many = [f"T{i}" for i in range(12)]
    shown = format_types(many)
    assert "T0" in shown and "T7" in shown
    assert "T8" not in shown
    assert "+4 more" in shown
    assert parse_schema_types('{"data":{}}') == []
    assert parse_schema_types("nope") == []


def test_skips_non_local_origin_without_allow_external():
    class Boom:
        def post_json(self, *args, **kwargs):
            raise AssertionError("must not probe off-local hosts")

        def fetch(self, *args, **kwargs):
            raise AssertionError("must not probe off-local hosts")

    pages, findings, endpoints = probe_graphql("http://example.com/", Boom(), set())
    assert pages == []
    assert len(findings) == 1
    assert findings[0].id == "graphql-probe-skipped"
    assert findings[0].category == "scan-note"
    assert endpoints == []


def _gql_handler(typename: str = "Query", types: list[str] | None = None):
    type_list = types or ["Query", "HiddenNote", "String"]

    def handle(incoming) -> tuple[int, dict[str, str], bytes]:
        query = ""
        if incoming.body:
            try:
                payload = json.loads(incoming.body.decode())
            except json.JSONDecodeError:
                payload = {}
            if isinstance(payload, dict):
                query = str(payload.get("query") or "")
        if "__schema" in query:
            body = json.dumps(
                {"data": {"__schema": {"types": [{"name": n} for n in type_list]}}}
            )
            return 200, {"Content-Type": "application/json"}, body.encode()
        body = json.dumps({"data": {"__typename": typename}})
        return 200, {"Content-Type": "application/json"}, body.encode()

    return handle


def test_post_graphql_is_discovered(fx):
    fx.html("/", "<p>home</p>")
    fx.html("/graphql-hidden", "<h1>unlinked</h1>")
    fx.on("POST", "/graphql", _gql_handler())
    result = crawl_url(fx.origin + "/", depth=0)
    paths = _paths(result)
    assert "/graphql" in paths
    assert "/graphql-hidden" not in paths
    assert "/api/graphql" not in paths
    hit = next(
        f for f in result.findings if f.id == "js-endpoint" and f.url.endswith("/graphql")
    )
    assert hit.category == "js-endpoint"
    assert hit.severity == "info"
    assert "HiddenNote" in hit.description
    assert any(e.endpoint == "/graphql" for e in result.js_endpoints)


def test_get_graphql_fallback(fx):
    fx.html("/", "<p>home</p>")

    def handle_get(_req: str) -> tuple[int, dict[str, str], bytes]:
        return (
            200,
            {"Content-Type": "application/json"},
            b'{"data":{"__typename":"Query"}}',
        )

    fx.route("/query", handle_get)
    result = crawl_url(fx.origin + "/", depth=0)
    assert "/query" in _paths(result)
    assert any(f.id == "js-endpoint" and f.url.endswith("/query") for f in result.findings)


def test_missing_and_non_graphql_not_recorded(fx):
    fx.html("/", "<p>home</p>")
    fx.on(
        "POST",
        "/graphql",
        lambda _i: (200, {"Content-Type": "application/json"}, b'{"data":{"users":[]}}'),
    )
    result = crawl_url(fx.origin + "/", depth=0)
    paths = _paths(result)
    assert paths == {"/"}
    assert not any(f.url.endswith("/graphql") for f in result.findings)
