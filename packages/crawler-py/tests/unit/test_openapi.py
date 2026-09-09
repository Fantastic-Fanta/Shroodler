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


OPENAPI3_RICH = {
    "openapi": "3.0.3",
    "info": {"title": "demo", "version": "1.0.0"},
    "servers": [{"url": "/"}],
    "security": [{"bearerAuth": []}],
    "paths": {
        "/users": {
            "get": {
                "parameters": [
                    {
                        "name": "q",
                        "in": "query",
                        "schema": {"type": "string"},
                        "example": "alice",
                    }
                ],
                "security": [],
            }
        },
        "/accounts/{accountId}": {
            "get": {
                "parameters": [
                    {
                        "name": "accountId",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "integer", "example": 800002},
                    },
                    {
                        "name": "X-Trace",
                        "in": "header",
                        "schema": {"type": "string"},
                    },
                ]
            },
            "post": {
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "amount": {"type": "number", "example": 10},
                                    "note": {"type": "string"},
                                },
                            }
                        }
                    }
                }
            },
        },
    },
    "components": {
        "securitySchemes": {
            "bearerAuth": {"type": "http", "scheme": "bearer"},
            "apiKey": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
        }
    },
}

SWAGGER2_RICH = {
    "swagger": "2.0",
    "info": {"title": "demo", "version": "1.0.0"},
    "basePath": "/v2",
    "security": [{"api_key": []}],
    "paths": {
        "/pets/{petId}": {
            "get": {
                "parameters": [
                    {"name": "petId", "in": "path", "type": "integer", "example": 42},
                    {"name": "status", "in": "query", "type": "string"},
                ]
            }
        },
        "/login": {
            "post": {
                "security": [],
                "parameters": [
                    {"name": "user", "in": "formData", "type": "string", "example": "jsmith"}
                ],
            }
        },
    },
    "securityDefinitions": {
        "api_key": {"type": "apiKey", "in": "header", "name": "api_key"},
        "cookieAuth": {"type": "apiKey", "in": "cookie", "name": "JSESSIONID"},
    },
}

SWAGGER_UI_HTML = """
<!doctype html>
<html>
  <head><title>Swagger UI</title></head>
  <body>
    <div id="swagger-ui"></div>
    <script>
      window.ui = SwaggerUIBundle({
        url: "/v2/api-docs",
        dom_id: "#swagger-ui"
      });
    </script>
  </body>
</html>
"""

SWAGGER_UI_URLS_HTML = """
<script>
  SwaggerUIBundle({
    urls: [{url: "/swagger.json", name: "default"}]
  });
</script>
"""


class _FakeResp:
    def __init__(self, status=200, text="", url=""):
        self.status_code = status
        self.text = text
        self.content = text.encode() if isinstance(text, str) else text
        self.headers = {}
        self.url = url


class _FakeClient:
    def __init__(self, routes: dict[str, _FakeResp]):
        self.routes = routes
        self.calls: list[str] = []

    def request(self, method, url, **kw):
        self.calls.append(url)
        from urllib.parse import urlparse as _p

        path = _p(url).path
        resp = self.routes.get(path) or self.routes.get(url)
        if resp is None:
            return _FakeResp(404, "", url)
        if not resp.url:
            resp.url = url
        return resp

    def close(self):
        pass


def test_parse_openapi3_params_and_auth():
    from shroodler.openapi import parse_spec

    eps = parse_spec(OPENAPI3_RICH, "http://127.0.0.1/")
    by_key = {(e.method, urlparse(e.url).path): e for e in eps}
    users = by_key[("GET", "/users")]
    assert users.auth_required is False
    q = next(p for p in users.params if p["name"] == "q")
    assert q["in"] == "query"
    assert q["type"] == "string"
    assert q["example"] == "alice"

    acct = by_key[("GET", "/accounts/{accountId}")]
    assert acct.auth_required is True
    path_p = next(p for p in acct.params if p["name"] == "accountId")
    assert path_p["in"] == "path"
    assert path_p["type"] == "integer"
    assert path_p["example"] == 800002
    header_p = next(p for p in acct.params if p["name"] == "X-Trace")
    assert header_p["in"] == "header"

    post = by_key[("POST", "/accounts/{accountId}")]
    assert post.auth_required is True
    names = {p["name"] for p in post.params if p["in"] == "body"}
    assert names == {"amount", "note"}
    amount = next(p for p in post.params if p["name"] == "amount")
    assert amount["example"] == 10


def test_parse_swagger2_params_and_auth():
    from shroodler.openapi import parse_spec

    eps = parse_spec(SWAGGER2_RICH, "http://127.0.0.1/")
    by_key = {(e.method, urlparse(e.url).path): e for e in eps}
    pets = by_key[("GET", "/v2/pets/{petId}")]
    assert pets.auth_required is True
    pet_id = next(p for p in pets.params if p["name"] == "petId")
    assert pet_id["in"] == "path"
    assert pet_id["type"] == "integer"
    assert pet_id["example"] == 42
    login = by_key[("POST", "/v2/login")]
    assert login.auth_required is False
    user = next(p for p in login.params if p["name"] == "user")
    assert user["in"] == "formData"
    assert user["example"] == "jsmith"


def test_parse_yaml_spec_via_parse_spec_text():
    from shroodler.openapi import parse_spec_text

    yaml_spec = (
        "openapi: '3.0.0'\n"
        "info:\n  title: y\n  version: '1'\n"
        "paths:\n  /from-yaml:\n    get:\n      parameters:\n"
        "        - name: id\n          in: query\n          schema:\n            type: integer\n"
    )
    eps = parse_spec_text(yaml_spec, "http://127.0.0.1/")
    assert len(eps) == 1
    assert eps[0].method == "GET"
    assert urlparse(eps[0].url).path == "/from-yaml"
    assert eps[0].params[0]["name"] == "id"
    assert eps[0].params[0]["type"] == "integer"


def test_spec_urls_from_swagger_index_html():
    from shroodler.openapi import spec_urls_from_html

    urls = spec_urls_from_html(SWAGGER_UI_HTML, "http://127.0.0.1/swagger/index.html")
    assert urls == ["http://127.0.0.1/v2/api-docs"]
    urls2 = spec_urls_from_html(SWAGGER_UI_URLS_HTML, "http://127.0.0.1/swagger/index.html")
    assert urls2 == ["http://127.0.0.1/swagger.json"]


def test_discover_specs_follows_swagger_ui_html():
    import json

    from shroodler.openapi import discover_specs
    from shroodler.pacer import Pacer

    spec_body = json.dumps(SWAGGER2_RICH)
    client = _FakeClient(
        {
            "/swagger/index.html": _FakeResp(200, SWAGGER_UI_HTML),
            "/v2/api-docs": _FakeResp(200, spec_body),
        }
    )
    found = discover_specs(
        "http://127.0.0.1/",
        client=client,
        pacer=Pacer(0),
    )
    assert len(found) == 1
    spec_url, spec = found[0]
    assert urlparse(spec_url).path == "/v2/api-docs"
    assert spec["swagger"] == "2.0"
    assert any(urlparse(u).path == "/swagger/index.html" for u in client.calls)
    assert any(urlparse(u).path == "/v2/api-docs" for u in client.calls)


def test_discover_specs_parses_json_and_yaml():
    import json as json_mod

    from shroodler.openapi import discover_specs
    from shroodler.pacer import Pacer

    yaml_body = (
        "openapi: '3.0.0'\n"
        "info:\n  title: y\n  version: '1'\n"
        "paths:\n  /from-yaml:\n    get: {}\n"
    )
    client = _FakeClient(
        {
            "/openapi.json": _FakeResp(200, json_mod.dumps(OPENAPI3_RICH)),
            "/openapi.yaml": _FakeResp(200, yaml_body),
        }
    )
    found = discover_specs("http://127.0.0.1/", client=client, pacer=Pacer(0))
    paths = {urlparse(u).path for u, _ in found}
    assert "/openapi.json" in paths
    assert "/openapi.yaml" in paths


def test_merge_openapi_into_state_upserts_and_round_trips(tmp_path, monkeypatch):
    from shroodler.openapi import merge_openapi_into_state, parse_spec
    from shroodler.program import load, save

    monkeypatch.setenv("HOME", str(tmp_path))
    state = load("lab")
    eps = parse_spec(OPENAPI3_RICH, "http://127.0.0.1/")
    spec_url = "http://127.0.0.1/openapi.json"
    added = merge_openapi_into_state(state, eps, spec_url)
    unique_urls = {ep.url for ep in eps}
    assert added == len(unique_urls)
    assert state.openapi_spec_url == spec_url
    assert len(state.openapi_endpoints) == len(eps)
    acct = "http://127.0.0.1/accounts/{accountId}"
    assert acct in state.endpoints
    assert state.endpoints[acct]["method"] == "POST"
    assert state.endpoints[acct]["source"] == "openapi"
    names = {p["name"] for p in state.endpoints[acct]["params"]}
    assert "accountId" in names
    assert "amount" in names
    hit = next(f for f in state.findings if f.id == "openapi-spec-found")
    assert hit.severity == "info"
    assert hit.category == "scan-note"
    assert hit.confidence == "confirmed"
    assert hit.url == spec_url
    save(state)
    loaded = load("lab")
    assert loaded.openapi_spec_url == spec_url
    assert len(loaded.openapi_endpoints) == len(eps)
    assert loaded.findings[0].id == "openapi-spec-found"


def test_merge_openapi_is_idempotent(tmp_path, monkeypatch):
    from shroodler.openapi import merge_openapi_into_state, parse_spec
    from shroodler.program import load

    monkeypatch.setenv("HOME", str(tmp_path))
    state = load("lab")
    eps = parse_spec(OPENAPI3_RICH, "http://127.0.0.1/")
    spec_url = "http://127.0.0.1/openapi.json"
    first = merge_openapi_into_state(state, eps, spec_url)
    second = merge_openapi_into_state(state, eps, spec_url)
    assert first > 0
    assert second == 0
    assert len([f for f in state.findings if f.id == "openapi-spec-found"]) == 1
    assert len(state.openapi_endpoints) == len(eps)

