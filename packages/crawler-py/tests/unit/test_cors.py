from __future__ import annotations

from urllib.parse import urlparse

from shroodler.crawler import crawl_url
from shroodler.extractors.cors import (
    ATTACKER_ORIGIN,
    findings_from_cors_headers,
    is_api_ish,
    is_static_asset,
    probe_cors,
)


def _ids(findings) -> list[str]:
    return [f.id for f in findings]


def test_cors_wildcard_credentials():
    findings = findings_from_cors_headers(
        {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        },
        "http://127.0.0.1/api/x",
    )
    assert _ids(findings) == ["cors-wildcard-credentials"]
    assert findings[0].category == "header"
    assert findings[0].severity == "high"


def test_cors_reflect_origin():
    findings = findings_from_cors_headers(
        {"Access-Control-Allow-Origin": ATTACKER_ORIGIN},
        "http://127.0.0.1/api/x",
    )
    assert _ids(findings) == ["cors-reflect-origin"]
    assert findings[0].severity == "medium"
    creds = findings_from_cors_headers(
        {
            "Access-Control-Allow-Origin": ATTACKER_ORIGIN,
            "Access-Control-Allow-Credentials": "true",
        },
        "http://127.0.0.1/api/x",
    )
    assert _ids(creds) == ["cors-reflect-origin"]
    assert creds[0].severity == "high"


def test_cors_allow_any():
    findings = findings_from_cors_headers(
        {"Access-Control-Allow-Origin": "*"},
        "http://127.0.0.1/api/x",
    )
    assert _ids(findings) == ["cors-allow-any"]
    assert findings[0].severity == "info"
    assert findings[0].category == "header"


def test_cors_negative_allowlist_and_absent():
    locked = findings_from_cors_headers(
        {"Access-Control-Allow-Origin": "https://app.example"},
        "http://127.0.0.1/api/x",
    )
    assert locked == []
    assert findings_from_cors_headers({}, "http://127.0.0.1/api/x") == []
    assert findings_from_cors_headers(
        {"Access-Control-Allow-Credentials": "true"},
        "http://127.0.0.1/api/x",
    ) == []


def test_api_ish_skips_static():
    assert is_static_asset("http://127.0.0.1/static/app.js")
    assert not is_api_ish("http://127.0.0.1/static/app.js", "application/javascript")
    assert is_api_ish("http://127.0.0.1/api/users", "text/plain")
    assert is_api_ish("http://127.0.0.1/users", "application/json")
    assert not is_api_ish("http://127.0.0.1/login", "text/html")


def test_skips_non_local_origin_without_allow_external():
    class Boom:
        def request(self, *args, **kwargs):
            raise AssertionError("must not probe off-local hosts")

    findings = probe_cors("http://example.com/", Boom(), ["http://example.com/api/x"])
    assert len(findings) == 1
    assert findings[0].id == "cors-probe-skipped"
    assert findings[0].category == "scan-note"


def test_allow_external_permits_non_local_origin():
    calls = []

    class Recorder:
        def request(self, method, url, headers=None):
            calls.append((method, url))

            class Resp:
                headers: dict[str, str] = {}

            return Resp()

    out = probe_cors(
        "http://example.com/",
        Recorder(),
        ["http://example.com/api/x"],
        allow_external=True,
    )
    assert out == []
    assert calls, "expected the probe to actually fire when allow_external=True"


def test_crawl_maps_each_cors_id(fx):
    fx.html(
        "/",
        '<a href="/api/cors-reflect">r</a>'
        '<a href="/api/cors-star-creds">c</a>'
        '<a href="/api/cors-star">s</a>'
        '<a href="/api/cors-locked">l</a>'
        '<script src="/static/app.js"></script>',
    )

    def reflect(incoming):
        origin = incoming.headers.get("Origin") or incoming.headers.get("origin") or ""
        return (
            200,
            {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
            },
            b'{"ok":true}',
        )

    fx.on("GET", "/api/cors-reflect", reflect)
    fx.on("OPTIONS", "/api/cors-reflect", reflect)
    fx.route(
        "/api/cors-star-creds",
        lambda _req: (
            200,
            {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            },
            b'{"ok":true}',
        ),
    )
    fx.route(
        "/api/cors-star",
        lambda _req: (
            200,
            {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
            b'{"ok":true}',
        ),
    )
    fx.route(
        "/api/cors-locked",
        lambda _req: (
            200,
            {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "https://app.example",
            },
            b'{"ok":true}',
        ),
    )
    fx.route(
        "/static/app.js",
        lambda _req: (200, {"Content-Type": "application/javascript"}, b"console.log(1)"),
    )

    result = crawl_url(fx.origin + "/", depth=1, ignore_robots=True)
    ids = {(f.id, urlparse(f.url).path) for f in result.findings}
    assert ("cors-reflect-origin", "/api/cors-reflect") in ids
    assert ("cors-wildcard-credentials", "/api/cors-star-creds") in ids
    assert ("cors-allow-any", "/api/cors-star") in ids
    assert ("cors-allow-any", "/api/cors-star-creds") not in ids
    assert ("cors-reflect-origin", "/api/cors-locked") not in ids
    assert ("cors-wildcard-credentials", "/api/cors-star") not in ids
    assert not any(path == "/static/app.js" for method, path in fx.calls if method == "OPTIONS")
    assert any(method == "OPTIONS" and path.startswith("/api/cors-") for method, path in fx.calls)


def test_get_origin_fallback(fx):
    fx.html("/", '<a href="/api/only-get">x</a>')

    def handle(incoming):
        headers = {"Content-Type": "application/json"}
        if incoming.method == "GET":
            origin = incoming.headers.get("Origin") or incoming.headers.get("origin") or ""
            headers["Access-Control-Allow-Origin"] = origin
        return 200, headers, b'{"ok":true}'

    fx.on("GET", "/api/only-get", handle)
    fx.on("OPTIONS", "/api/only-get", handle)
    result = crawl_url(fx.origin + "/", depth=1, ignore_robots=True)
    assert any(
        f.id == "cors-reflect-origin" and urlparse(f.url).path == "/api/only-get"
        for f in result.findings
    )
