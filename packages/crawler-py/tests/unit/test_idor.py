from __future__ import annotations

import json

from shroodler.extractors.idor import _format_like, find_id_candidates, probe_idor
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


def test_format_like_preserves_zero_padding():
    # "/orders/007" -> id-1 must stay "006", not become "6" -- some
    # legacy ID schemes require exact width, and losing it would 404 the
    # adjacent candidate for a formatting reason unrelated to authz,
    # a false negative rather than the intended test.
    assert _format_like("007", 6) == "006"
    assert _format_like("007", 8) == "008"


def test_format_like_does_not_truncate_when_new_value_is_wider():
    # Original had no meaningful padding to preserve (008 -> the not-found
    # baseline offset makes a much longer number); zfill only pads, never
    # truncates, so the real value is never silently corrupted.
    assert _format_like("8", 987654329) == "987654329"


def test_idor_preserves_zero_padded_id_width_end_to_end(fx):
    origin = fx.origin
    _json_route(fx, "/orders/007", {"id": 7, "total": 42})
    _json_route(fx, "/orders/006", {"id": 6, "total": 17})
    _json_route(fx, "/orders/008", {"id": 8, "total": 99})
    _json_route(fx, "/orders/987654336", {"error": "not found"}, status=404)

    fetcher = StaticFetcher()
    try:
        pages = [Page(url=f"{origin}/orders/007", status_code=200)]
        findings = probe_idor(fetcher, pages)
    finally:
        fetcher.close()
    urls_hit = {f.evidence for f in findings}
    assert f"{origin}/orders/006" in urls_hit
    assert f"{origin}/orders/008" in urls_hit


def test_idor_finding_is_medium_severity_with_ownership_caveat(fx):
    # Downgraded from an earlier "high": a single-session probe cannot
    # tell whether the adjacent ID belongs to a different account or is
    # just another of the current account's own records, so this must
    # read as a lead to confirm, not a proven finding.
    origin = fx.origin
    _json_route(fx, "/orders/123", {"id": 123, "total": 42})
    _json_route(fx, "/orders/122", {"id": 122, "total": 17})
    _json_route(fx, "/orders/987654444", {"error": "not found"}, status=404)

    fetcher = StaticFetcher()
    try:
        pages = [Page(url=f"{origin}/orders/123", status_code=200)]
        findings = probe_idor(fetcher, pages)
    finally:
        fetcher.close()
    hit = next(f for f in findings if f.id == "idor-adjacent-id-accessible")
    assert hit.severity == "medium"
    assert "confirm" in hit.description.lower()


def test_finds_every_numeric_position_not_just_the_first():
    # Regression test: dedup used to be keyed on the whole original_url,
    # so a URL with more than one numeric position (a tenant/collection id
    # AND the actual object id) silently kept only the first one found and
    # dropped the rest -- fuzzing the wrong parameter.
    pages = [Page(url="http://x/users/5/orders/123", status_code=200)]
    values = {c.original_value for c in find_id_candidates(pages)}
    assert values == {5, 123}


def test_finds_every_query_param_not_just_the_first():
    pages = [Page(url="http://x/view?account=1&order=456", status_code=200)]
    values = {c.original_value for c in find_id_candidates(pages)}
    assert values == {1, 456}


def test_pagination_style_query_params_are_not_treated_as_ids():
    pages = [
        Page(url="http://x/list?page=2", status_code=200),
        Page(url="http://x/list?year=2024", status_code=200),
        Page(url="http://x/list?limit=50&offset=10", status_code=200),
    ]
    assert list(find_id_candidates(pages)) == []


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
