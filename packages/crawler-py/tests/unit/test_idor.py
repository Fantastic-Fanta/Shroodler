from __future__ import annotations

import json

from shroodler.extractors.idor import find_id_candidates, probe_idor
from shroodler.models import Page
from shroodler.modes.static import StaticFetcher


def _json_route(fx, path: str, body: dict, status: int = 200):
    payload = json.dumps(body).encode("utf-8")

    def handle(_req: str):
        return status, {"Content-Type": "application/json"}, payload

    fx.route(path, handle)


def test_finds_numeric_path_and_query_candidates():
    pages = [
        Page(url="http://x/orders/123", status_code=200),
        Page(url="http://x/view?id=456", status_code=200),
        Page(url="http://x/about", status_code=200),
    ]
    urls = {c.original_url for c in find_id_candidates(pages)}
    assert urls == {"http://x/orders/123", "http://x/view?id=456"}


def test_idor_fires_when_adjacent_id_returns_same_shaped_json(fx):
    origin = fx.origin
    _json_route(fx, "/orders/123", {"id": 123, "total": 42})
    _json_route(fx, "/orders/122", {"id": 122, "total": 17})
    _json_route(fx, "/orders/124", {"id": 124, "total": 99})
    # not-found baseline: original 123 + 987654321 offset
    _json_route(fx, "/orders/987654444", {"error": "not found"}, status=404)

    fetcher = StaticFetcher()
    try:
        pages = [Page(url=f"{origin}/orders/123", status_code=200)]
        findings = probe_idor(fetcher, pages)
    finally:
        fetcher.close()
    ids = {f.id for f in findings}
    assert "idor-adjacent-id-accessible" in ids
    urls_hit = {f.evidence for f in findings}
    assert f"{origin}/orders/122" in urls_hit
    assert f"{origin}/orders/124" in urls_hit


def test_idor_does_not_fire_when_adjacent_id_is_not_found(fx):
    origin = fx.origin
    _json_route(fx, "/orders/123", {"id": 123, "total": 42})
    # Adjacent IDs correctly 404 -- no other route registered for them,
    # FixtureServer's default handler returns 404.
    _json_route(fx, "/orders/987654444", {"error": "not found"}, status=404)

    fetcher = StaticFetcher()
    try:
        pages = [Page(url=f"{origin}/orders/123", status_code=200)]
        findings = probe_idor(fetcher, pages)
    finally:
        fetcher.close()
    assert findings == []


def test_idor_skips_target_that_never_distinguishes_valid_ids(fx):
    # Every ID, including the not-found-baseline sentinel, returns the
    # same 200/JSON shape -- the target doesn't differentiate valid from
    # invalid IDs at all, so nothing here can prove access to a genuinely
    # different object. Must not report a finding.
    origin = fx.origin
    body = {"id": 1, "ok": True}
    _json_route(fx, "/orders/123", body)
    _json_route(fx, "/orders/122", body)
    _json_route(fx, "/orders/124", body)
    _json_route(fx, "/orders/987654444", body)

    fetcher = StaticFetcher()
    try:
        pages = [Page(url=f"{origin}/orders/123", status_code=200)]
        findings = probe_idor(fetcher, pages)
    finally:
        fetcher.close()
    assert findings == []


def test_idor_skips_non_json_responses(fx):
    origin = fx.origin
    fx.html("/orders/123", "<p>order 123</p>")
    fx.html("/orders/122", "<p>order 122</p>")
    fx.html("/orders/124", "<p>order 124</p>")
    fx.html("/orders/987654444", "<p>not found</p>", status=404)

    fetcher = StaticFetcher()
    try:
        pages = [Page(url=f"{origin}/orders/123", status_code=200)]
        findings = probe_idor(fetcher, pages)
    finally:
        fetcher.close()
    assert findings == []


def test_idor_skips_when_adjacent_shape_differs_from_original(fx):
    origin = fx.origin
    _json_route(fx, "/orders/123", {"id": 123, "total": 42, "owner": "me"})
    # Adjacent ID returns 200 JSON, but a differently-shaped object (e.g.
    # a generic "access denied" body some APIs return with a 200 status)
    _json_route(fx, "/orders/122", {"error": "forbidden"})
    _json_route(fx, "/orders/124", {"error": "forbidden"})
    _json_route(fx, "/orders/987654444", {"error": "forbidden"})

    fetcher = StaticFetcher()
    try:
        pages = [Page(url=f"{origin}/orders/123", status_code=200)]
        findings = probe_idor(fetcher, pages)
    finally:
        fetcher.close()
    assert findings == []
