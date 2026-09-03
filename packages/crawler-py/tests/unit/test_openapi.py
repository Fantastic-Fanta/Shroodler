from __future__ import annotations

from urllib.parse import urlparse

from shroodler.crawler import crawl_url
from shroodler.extractors.openapi import parse_spec_paths, urls_from_spec

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
