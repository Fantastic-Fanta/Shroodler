from __future__ import annotations

from shroodler.models import Finding
from shroodler.openapi import OpenApiEndpoint
from shroodler.pacer import Pacer
from shroodler.probes.openapi_probe import fill_path_params, probe_openapi_endpoints


class FakeResp:
    def __init__(self, status=200, text=""):
        self.status_code = status
        self.text = text
        self.content = text.encode() if isinstance(text, str) else text
        self.headers = {}


class FakeClient:
    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def request(self, method, url, **kw):
        self.calls.append((method, url, kw))
        return self.handler(method, url, kw)

    def close(self):
        pass


def test_fill_path_params_uses_example_then_defaults():
    url = "http://127.0.0.1/api/account/{accountId}/note/{note}"
    filled = fill_path_params(
        url,
        [
            {"name": "accountId", "in": "path", "type": "integer", "example": 800002},
            {"name": "note", "in": "path", "type": "string"},
        ],
    )
    assert filled == "http://127.0.0.1/api/account/800002/note/test"
    assert fill_path_params(
        "http://127.0.0.1/items/{id}",
        [{"name": "id", "in": "path", "type": "integer"}],
    ) == "http://127.0.0.1/items/1"


def test_probe_openapi_reuses_inner_probes(monkeypatch):
    calls: list[str] = []

    monkeypatch.setattr(
        "shroodler.probes.openapi_probe.probe_sqli",
        lambda url, method, params, cookie, **kw: calls.append("sqli") or [
            Finding(
                id="sqli",
                severity="critical",
                category="payload",
                url=url,
                description="sqli",
                confidence="confirmed",
            )
        ],
    )
    monkeypatch.setattr(
        "shroodler.probes.openapi_probe.probe_xss",
        lambda *a, **k: calls.append("xss") or [],
    )
    monkeypatch.setattr(
        "shroodler.probes.openapi_probe.probe_path_traversal",
        lambda *a, **k: calls.append("path") or [],
    )
    monkeypatch.setattr(
        "shroodler.probes.openapi_probe.probe_idor",
        lambda url, owner, peer, **kw: calls.append("idor") or [
            Finding(
                id="idor",
                severity="high",
                category="auth",
                url=url,
                description="idor",
                confidence="confirmed",
            )
        ],
    )

    eps = [
        {
            "url": "http://127.0.0.1/api/account/{accountId}",
            "method": "GET",
            "params": [
                {"name": "accountId", "in": "path", "type": "integer", "example": 800002},
                {"name": "q", "in": "query", "type": "string"},
            ],
            "auth_required": False,
        }
    ]
    findings = probe_openapi_endpoints(
        eps,
        cookie_header="session=owner",
        peer_cookie="session=peer",
        pacer=Pacer(0),
        client=FakeClient(lambda *a, **k: FakeResp(401, "")),
    )
    assert {f.id for f in findings} == {"sqli", "idor"}
    assert "sqli" in calls and "xss" in calls and "path" in calls and "idor" in calls
    assert findings[0].url == "http://127.0.0.1/api/account/800002"


def test_probe_openapi_unauthenticated_access():
    client = FakeClient(lambda method, url, kw: FakeResp(200, '{"ok":true}'))
    findings = probe_openapi_endpoints(
        [
            {
                "url": "http://127.0.0.1/api/secret",
                "method": "GET",
                "params": [],
                "auth_required": True,
            }
        ],
        pacer=Pacer(0),
        client=client,
    )
    hit = next(f for f in findings if f.id == "openapi-unauthenticated")
    assert hit.severity == "high"
    assert hit.category == "auth"
    assert hit.confidence == "confirmed"
    assert hit.url == "http://127.0.0.1/api/secret"
    assert client.calls
    assert "headers" not in client.calls[0][2] or not any(
        k.lower() == "authorization" or k.lower() == "cookie"
        for k in (client.calls[0][2].get("headers") or {})
    )


def test_probe_openapi_skips_tested_payload(monkeypatch):
    monkeypatch.setattr(
        "shroodler.probes.openapi_probe.probe_sqli",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("should skip")),
    )
    findings = probe_openapi_endpoints(
        [
            {
                "url": "http://127.0.0.1/api/x",
                "method": "GET",
                "params": [{"name": "q", "in": "query"}],
                "tested_payload": True,
            }
        ],
        pacer=Pacer(0),
    )
    assert findings == []


def test_probe_openapi_fills_unknown_path_params():
    filled = fill_path_params("http://127.0.0.1/still/{missing}", [])
    assert filled == "http://127.0.0.1/still/test"
    findings = probe_openapi_endpoints(
        [
            OpenApiEndpoint(
                url="http://127.0.0.1/still/{missing}",
                method="GET",
                params=[],
                auth_required=False,
            )
        ],
        pacer=Pacer(0),
        client=FakeClient(lambda *a, **k: FakeResp(200, "x")),
    )
    assert findings == []


def test_probe_openapi_collects_per_endpoint_errors(monkeypatch):
    monkeypatch.setattr(
        "shroodler.probes.openapi_probe.probe_sqli",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    monkeypatch.setattr("shroodler.probes.openapi_probe.probe_xss", lambda *a, **k: [])
    monkeypatch.setattr(
        "shroodler.probes.openapi_probe.probe_path_traversal", lambda *a, **k: []
    )
    findings = probe_openapi_endpoints(
        [
            {
                "url": "http://127.0.0.1/search",
                "method": "GET",
                "params": [{"name": "q", "in": "query"}],
            },
            {
                "url": "http://127.0.0.1/ok",
                "method": "GET",
                "params": [],
                "auth_required": True,
            },
        ],
        pacer=Pacer(0),
        client=FakeClient(lambda *a, **k: FakeResp(401, "")),
    )
    assert not any(f.id == "sqli" for f in findings)
    assert not any(f.id == "openapi-unauthenticated" for f in findings)


def test_openapi_path_runs_open_redirect():
    # An endpoint with a redirect-shaped param that echoes it into Location:
    # the OpenAPI probe path must now catch the open redirect.
    def handler(method, url, kw):
        params = kw.get("params") or {}
        target = str(params.get("url", ""))
        if "evil.example.com" in target:
            r = FakeResp(302, "")
            r.headers = {"location": target}
            return r
        return FakeResp(200, "ok")

    ep = OpenApiEndpoint(
        url="http://127.0.0.1/api/go",
        method="GET",
        params=[{"name": "url", "in": "query", "type": "string"}],
    )
    client = FakeClient(handler)
    findings = probe_openapi_endpoints(
        [ep], cookie_header="", peer_cookie="", client=client, pacer=Pacer(0)
    )
    assert any(f.id == "open-redirect" for f in findings)
