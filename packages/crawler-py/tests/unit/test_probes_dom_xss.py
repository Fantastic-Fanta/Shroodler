from __future__ import annotations

from urllib.parse import unquote_plus

from shroodler.pacer import Pacer
from shroodler.probes.dom_xss import (
    _cookie_origin,
    probe_dom_xss,
    spa_search_view_url,
)


class FakePage:
    def __init__(self, *, flag=1, cookies="sessionid=abc"):
        self.flag = flag
        self.cookies = cookies
        self.gotos: list[str] = []
        self.evals: list[str] = []

    def goto(self, url, **kw):
        self.gotos.append(url)

    def evaluate(self, expr):
        self.evals.append(expr)
        text = str(expr or "")
        if "document.cookie" in text:
            return self.cookies
        if "__shroodler_" in text:
            return self.flag
        return None


def test_dom_xss_confirmed_when_nonce_flag_is_set():
    page = FakePage(flag=1, cookies="")
    findings = probe_dom_xss(
        "http://127.0.0.1/search",
        "GET",
        [{"name": "q", "value": "x"}],
        "",
        page=page,
        pacer=Pacer(0),
    )
    hit = next(f for f in findings if f.id == "dom-xss")
    assert hit.severity == "high"
    assert hit.confidence == "confirmed"
    assert hit.category == "payload"
    assert "param=q" in (hit.evidence or "")
    assert page.gotos
    assert "<img src=x onerror=window.__shroodler_" in unquote_plus(page.gotos[0])


def test_dom_xss_cookie_accessible_when_session_cookie_readable():
    page = FakePage(flag=1, cookies="sessionid=abc; other=1")
    findings = probe_dom_xss(
        "http://127.0.0.1/search?q=1",
        "GET",
        [{"name": "q"}],
        "sessionid=abc",
        page=page,
        pacer=Pacer(0),
    )
    ids = {f.id for f in findings}
    assert "dom-xss" in ids
    cookie = next(f for f in findings if f.id == "dom-xss-cookie-accessible")
    assert cookie.severity == "critical"
    assert cookie.confidence == "confirmed"


def test_dom_xss_no_finding_when_payload_does_not_execute():
    page = FakePage(flag=0, cookies="sessionid=abc")
    findings = probe_dom_xss(
        "http://127.0.0.1/search",
        "GET",
        [{"name": "q"}],
        "",
        page=page,
        pacer=Pacer(0),
    )
    assert findings == []


def test_dom_xss_skips_when_playwright_missing(monkeypatch):
    import shroodler.probes.dom_xss as mod

    monkeypatch.setattr(mod, "_launch_page", lambda cookie_header, url="": None)
    findings = probe_dom_xss(
        "http://127.0.0.1/search",
        "GET",
        [{"name": "q"}],
        "",
        pacer=Pacer(0),
    )
    assert findings == []


def test_dom_xss_hash_route_search_goto():
    page = FakePage(flag=1, cookies="")
    findings = probe_dom_xss(
        "http://127.0.0.1/#/search",
        "GET",
        [{"name": "q"}],
        "",
        page=page,
        pacer=Pacer(0),
    )
    assert any(f.id == "dom-xss" for f in findings)
    assert page.gotos
    decoded = unquote_plus(page.gotos[0])
    assert "#/search?q=" in decoded
    assert "<img src=x onerror=window.__shroodler_" in decoded


def test_spa_search_view_url_maps_rest_search():
    assert (
        spa_search_view_url("http://localhost:3000/rest/products/search")
        == "http://localhost:3000/#/search"
    )
    assert spa_search_view_url("http://localhost:3000/rest/products/1") is None
    assert spa_search_view_url("/rest/products/search") is None


def test_cookie_origin_uses_localhost_port():
    assert (
        _cookie_origin("http://localhost:3000/rest/products/search")
        == "http://localhost:3000/"
    )
    assert _cookie_origin("") == "http://127.0.0.1/"
