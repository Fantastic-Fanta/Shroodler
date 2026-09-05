from __future__ import annotations

import pytest

from shroodler.authz_diff import run


def _doc(origin: str, urls: list[str]) -> dict:
    return {"target": origin + "/", "pages": [{"url": u} for u in urls]}


def test_refuses_external_without_allow_external():
    with pytest.raises(ValueError, match="non-local"):
        run({"target": "https://example.com/", "pages": []})


def test_allow_external_bypasses_guard():
    out = run({"target": "https://example.com/", "pages": []}, allow_external=True)
    assert out == {"target": "https://example.com/", "findings": []}


def test_flags_broken_access_control_when_anon_denied(fx):
    fx.on(
        "GET",
        "/admin/report/1",
        lambda inc: (200, {}, b"secret report")
        if "session=admin-or-user" in inc.cookies
        else (403, {}, b"forbidden"),
    )
    doc = _doc(fx.origin, [fx.origin + "/admin/report/1"])
    out = run(doc, cookie_header="session=admin-or-user")
    ids = {f["id"] for f in out["findings"]}
    assert "authz-broken-access-control" in ids


def test_no_finding_when_anon_also_allowed(fx):
    fx.on("GET", "/public/page", lambda inc: (200, {}, b"public"))
    doc = _doc(fx.origin, [fx.origin + "/public/page"])
    out = run(doc, cookie_header="session=whatever")
    assert out["findings"] == []


def test_no_finding_when_lower_priv_denied(fx):
    fx.on(
        "GET",
        "/admin/only",
        lambda inc: (200, {}, b"secret") if "session=real-admin" in inc.cookies else (403, {}, b"nope"),
    )
    doc = _doc(fx.origin, [fx.origin + "/admin/only"])
    out = run(doc, cookie_header="session=not-admin")
    assert out["findings"] == []


def test_no_anon_check_reports_any_reachable_url(fx):
    fx.on("GET", "/somewhere", lambda inc: (200, {}, b"ok"))
    doc = _doc(fx.origin, [fx.origin + "/somewhere"])
    out = run(doc, cookie_header="session=x", check_anonymous=False)
    ids = {f["id"] for f in out["findings"]}
    assert "authz-still-accessible" in ids


def test_dedupes_repeated_urls(fx):
    fx.on("GET", "/dup", lambda inc: (200, {}, b"ok"))
    doc = _doc(fx.origin, [fx.origin + "/dup", fx.origin + "/dup"])
    out = run(doc, cookie_header="session=x", check_anonymous=False)
    assert len(out["findings"]) == 1
