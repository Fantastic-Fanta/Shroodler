from __future__ import annotations

from datetime import timedelta

from shroodler.pacer import Pacer
from shroodler.probes.cache_poisoning import probe_cache_poisoning


class FakeResp:
    def __init__(self, status=200, text="", headers=None):
        self.status_code = status
        self.text = text
        self.content = text.encode()
        self.elapsed = timedelta(seconds=0.0)
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


def _injected_marker(kw) -> str:
    headers = kw.get("headers") or {}
    for name in (
        "X-Forwarded-Host",
        "X-Forwarded-Scheme",
        "X-Forwarded-Proto",
        "X-Forwarded-Port",
        "X-Host",
        "X-Original-URL",
        "X-Rewrite-URL",
    ):
        if name in headers:
            return headers[name]
    return ""


def test_reflected_and_cacheable_is_a_finding():
    def handler(method, url, kw):
        marker = _injected_marker(kw)
        # Reflects the unkeyed header into the body, and the response is cacheable.
        return FakeResp(
            200,
            text=f'<link href="https://{marker}/app.css">',
            headers={"Cache-Control": "public, max-age=600", "Age": "7"},
        )

    findings = probe_cache_poisoning(
        "http://127.0.0.1/home",
        "session=owner",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    hit = next(f for f in findings if f.id == "cache-poisoning-unkeyed-header")
    assert hit.severity == "high"
    assert hit.confidence == "heuristic"
    assert hit.category == "payload"


def test_reflected_but_not_cacheable_is_not_a_finding():
    def handler(method, url, kw):
        marker = _injected_marker(kw)
        return FakeResp(
            200,
            text=f"<a href='https://{marker}'>x</a>",
            headers={"Cache-Control": "no-store, private"},
        )

    findings = probe_cache_poisoning(
        "http://127.0.0.1/home",
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    assert findings == []


def test_cacheable_but_not_reflected_is_not_a_finding():
    def handler(method, url, kw):
        return FakeResp(
            200,
            text="<p>static page, no reflection</p>",
            headers={"Cache-Control": "public", "X-Cache": "HIT"},
        )

    findings = probe_cache_poisoning(
        "http://127.0.0.1/home",
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    assert findings == []


def test_uses_a_cache_buster_query_param():
    seen_urls = []

    def handler(method, url, kw):
        seen_urls.append(url)
        return FakeResp(200, text="nothing", headers={})

    probe_cache_poisoning(
        "http://127.0.0.1/home?q=1",
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    # Every request carries the throwaway cache-buster and preserves existing query.
    assert seen_urls, "probe made no request"
    assert all("shroodler_cb=" in u for u in seen_urls)
    assert all("q=1" in u for u in seen_urls)


def test_max_age_zero_is_not_cacheable():
    def handler(method, url, kw):
        marker = _injected_marker(kw)
        return FakeResp(
            200,
            text=f"https://{marker}",
            headers={"Cache-Control": "max-age=0"},
        )

    findings = probe_cache_poisoning(
        "http://127.0.0.1/home",
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    assert findings == []
