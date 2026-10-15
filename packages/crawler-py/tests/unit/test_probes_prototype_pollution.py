from __future__ import annotations

import json

from shroodler.pacer import Pacer
from shroodler.probes.prototype_pollution import looks_like_api, probe_prototype_pollution


class FakeResp:
    def __init__(self, status=200, text="", headers=None):
        self.status_code = status
        self.text = text
        self.content = text.encode()
        self.headers = headers or {}


class FakeClient:
    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def request(self, method, url, **kw):
        self.calls.append((method, url, kw))
        return self.handler(method, url, kw)

    def close(self):
        pass


def _blob(url, kw) -> str:
    parts = [url]
    params = kw.get("params") or {}
    if isinstance(params, dict):
        parts.extend(str(v) for v in params.values())
        parts.extend(str(k) for k in params)
    data = kw.get("data")
    if isinstance(data, dict):
        parts.extend(str(v) for v in data.values())
    payload = kw.get("json")
    if payload is not None:
        parts.append(json.dumps(payload))
    return " ".join(parts)


def test_looks_like_api_requires_json_or_api_path():
    assert looks_like_api("http://127.0.0.1/api/users")
    assert looks_like_api("http://127.0.0.1/x", "application/json")
    assert not looks_like_api("http://127.0.0.1/page", "text/html")


def test_prototype_pollution_reflected_in_json():
    def handler(method, url, kw):
        blob = _blob(url, kw)
        if "shroodlerPP" in blob:
            nonce = ""
            for token in blob.replace("{", " ").replace("}", " ").replace('"', " ").split():
                if len(token) == 16 and all(c in "0123456789abcdef" for c in token):
                    nonce = token
            if not nonce:
                return FakeResp(200, "{}")
            return FakeResp(200, json.dumps({"shroodlerPP": nonce, "ok": True}))
        return FakeResp(200, "{}")

    findings = probe_prototype_pollution(
        "http://127.0.0.1/api/settings",
        "POST",
        [],
        "",
        content_type="application/json",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    hit = next(f for f in findings if f.id == "prototype-pollution-reflected")
    assert hit.severity == "low"  # reflection is not proof of pollution
    assert hit.confidence == "heuristic"
    assert hit.category == "payload"


def test_prototype_pollution_behavior_on_500():
    def handler(method, url, kw):
        blob = _blob(url, kw)
        if "shroodlerPP" in blob or "__proto__" in blob:
            return FakeResp(500, "boom")
        return FakeResp(200, "{}")

    findings = probe_prototype_pollution(
        "http://127.0.0.1/api/item",
        "GET",
        [{"name": "q"}],
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    hit = next(f for f in findings if f.id == "prototype-pollution-behavior")
    assert hit.severity == "medium"
    assert hit.confidence == "heuristic"


def test_prototype_pollution_persistent_on_followup():
    polluted = {"on": False}

    def handler(method, url, kw):
        blob = _blob(url, kw)
        if "shroodlerPP" in blob:
            for token in blob.replace("{", " ").replace("}", " ").replace('"', " ").split():
                if len(token) == 16 and all(c in "0123456789abcdef" for c in token):
                    polluted["nonce"] = token
                    polluted["on"] = True
            return FakeResp(200, "{}")
        if polluted.get("on"):
            return FakeResp(200, json.dumps({"shroodlerPP": polluted["nonce"]}))
        return FakeResp(200, "{}")

    findings = probe_prototype_pollution(
        "http://127.0.0.1/api/config",
        "POST",
        [],
        "",
        content_type="application/json",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    hit = next(f for f in findings if f.id == "prototype-pollution-persistent")
    assert hit.severity == "critical"
    assert hit.confidence == "confirmed"


def test_prototype_pollution_skips_html_pages():
    findings = probe_prototype_pollution(
        "http://127.0.0.1/about",
        "GET",
        [{"name": "q"}],
        "",
        content_type="text/html",
        client=FakeClient(lambda *a, **k: FakeResp(200, "<html></html>")),
        pacer=Pacer(0),
    )
    assert findings == []


def test_waf_block_page_echo_is_not_reflection():
    # Regression (StudioFile): a WAF/Cloudflare block page echoes the offending
    # request, so the marker appears in its body even though the app never
    # reflected it. This must NOT be reported as prototype-pollution-reflected.
    def handler(method, url, kw):
        blob = _blob(url, kw)
        if "shroodlerPP" in blob:
            # "Just a moment" is a strong Cloudflare challenge signature; the
            # page echoes the request (marker + nonce) as block pages often do.
            return FakeResp(403, "Just a moment... " + blob)
        return FakeResp(200, "{}")

    findings = probe_prototype_pollution(
        "http://127.0.0.1/api/templates/1/build",
        "GET",
        [{"name": "id"}],
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    assert [f for f in findings if f.id == "prototype-pollution-reflected"] == []


def test_prototype_pollution_challenge_is_coverage_gap():
    def handler(method, url, kw):
        blob = _blob(url, kw)
        if "proto" in blob or "constructor" in blob:
            return FakeResp(403, "Just a moment...", headers={"content-type": "text/html"})
        return FakeResp(200, "{}", headers={"content-type": "application/json"})

    findings = probe_prototype_pollution(
        "http://127.0.0.1/api/items",
        "GET",
        [{"name": "q"}],
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    assert [f for f in findings if f.id.startswith("prototype-pollution")] == []
    gap = next(f for f in findings if f.id == "probe-challenged-prototype-pollution")
    assert gap.category == "waf-challenge"
