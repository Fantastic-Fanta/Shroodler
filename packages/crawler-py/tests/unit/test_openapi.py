from __future__ import annotations

from urllib.parse import urlparse

from shroodler.crawler import crawl_url
from shroodler.extractors.openapi import parse_spec_paths, urls_from_seed_text, urls_from_spec

OPENAPI3 = """
{
  "openapi": "3.0.3",
  "info": {"title": "demo", "version": "1.0.0"},
  "paths": {
    "/users": {"get": {}},
    "/internal/inventory": {"get": {"summary": "unlinked"}}
  }
}
"""

SWAGGER2 = """
{
  "swagger": "2.0",
  "info": {"title": "demo", "version": "1.0.0"},
  "paths": {
    "/v2/hidden": {"get": {}}
  }
}
"""

NOT_A_SPEC = """
{"paths": {"/nope": {}}, "name": "random json"}
"""


def test_parse_openapi3_paths():
    assert parse_spec_paths(OPENAPI3) == ["/users", "/internal/inventory"]


def test_parse_swagger2_paths():
    assert parse_spec_paths(SWAGGER2) == ["/v2/hidden"]


def test_parse_rejects_non_spec_json():
    assert parse_spec_paths(NOT_A_SPEC) == []
    assert parse_spec_paths("not json") == []
    assert parse_spec_paths("") == []


def test_parse_yaml_openapi():
    yaml_spec = (
        "openapi: '3.0.0'\n"
        "info:\n  title: y\n  version: '1'\n"
        "paths:\n  /from-yaml:\n    get: {}\n"
    )
    assert parse_spec_paths(yaml_spec) == ["/from-yaml"]


def test_urls_join_origin_only():
    urls = urls_from_spec("http://127.0.0.1:9/", OPENAPI3)
    assert urls == [
        "http://127.0.0.1:9/users",
        "http://127.0.0.1:9/internal/inventory",
    ]


def test_unlinked_spec_path_is_crawled(fx):
    spec = """
    {
      "openapi": "3.0.3",
      "info": {"title": "demo", "version": "1.0.0"},
      "paths": {"/internal/inventory": {"get": {}}}
    }
    """
    fx.html("/", "<h1>home</h1>")
    fx.route(
        "/openapi.json",
        lambda _req: (200, {"Content-Type": "application/json"}, spec.encode()),
    )
    fx.route(
        "/internal/inventory",
        lambda _req: (
            200,
            {"Content-Type": "application/json"},
            b'{"items":["widget"]}',
        ),
    )
    result = crawl_url(fx.origin + "/", depth=0)
    paths = {urlparse(p.url).path for p in result.pages}
    assert "/openapi.json" in paths
    assert "/internal/inventory" in paths
    assert "/swagger.json" not in paths


def test_missing_spec_not_recorded(fx):
    fx.html("/", "<p>home</p>")
    result = crawl_url(fx.origin + "/", depth=0)
    paths = {urlparse(p.url).path for p in result.pages}
    assert paths == {"/"}


POSTMAN = """
{
  "info": {
    "name": "demo",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "item": [
    {
      "name": "users",
      "request": {"method": "GET", "url": "{{baseUrl}}/postman-users"}
    },
    {
      "name": "folder",
      "item": [
        {
          "name": "nested",
          "request": {
            "method": "GET",
            "url": {"raw": "{{baseUrl}}/postman-nested", "path": ["postman-nested"]}
          }
        }
      ]
    },
    {
      "name": "off-origin",
      "request": {"method": "GET", "url": "https://example.com/nope"}
    }
  ]
}
"""


def test_postman_and_openapi_seed_text():
    urls = urls_from_seed_text("http://127.0.0.1:9/", POSTMAN)
    assert urls == [
        "http://127.0.0.1:9/postman-users",
        "http://127.0.0.1:9/postman-nested",
    ]
    urls2 = urls_from_seed_text("http://127.0.0.1:9/", OPENAPI3)
    assert "/users" in "".join(urls2)
    assert urls_from_seed_text("http://127.0.0.1:9/", NOT_A_SPEC) == []


def test_local_spec_file_seeds_unlinked_path(fx, tmp_path):
    fx.html("/", "<h1>home</h1>")
    fx.route(
        "/from-spec",
        lambda _req: (200, {"Content-Type": "application/json"}, b'{"ok":true}'),
    )
    spec = tmp_path / "api.json"
    spec.write_text(
        '{"openapi":"3.0.3","info":{"title":"d","version":"1"},'
        '"paths":{"/from-spec":{"get":{}}}}',
        encoding="utf-8",
    )
    extra = urls_from_seed_text(fx.origin + "/", spec.read_text(encoding="utf-8"))
    result = crawl_url(fx.origin + "/", depth=0, ignore_robots=True, extra_seeds=extra)
    paths = {urlparse(p.url).path for p in result.pages}
    assert "/from-spec" in paths


def test_cli_parses_spec_flag():
    from shroodler.cli import build_parser

    args = build_parser().parse_args(
        ["crawl", "http://127.0.0.1:8081", "--spec", "a.yaml", "--spec", "b.json"]
    )
    assert args.spec == ["a.yaml", "b.json"]
