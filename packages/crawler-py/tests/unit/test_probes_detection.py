"""Tests for the X-Forwarded-For rate-limit-bypass and unauth-exposure probes."""

from __future__ import annotations

from shroodler.probes import rate_limit as rl
from shroodler.probes import unauth_exposure as ue


class Resp:
    def __init__(self, status=200, body='{"x":1}', ctype="application/json", headers=None):
        self.status_code = status
        self.text = body
        self.content = body.encode()
        h = {"content-type": ctype}
        h.update(headers or {})
        self.headers = h


# --- X-Forwarded-For rate-limit bypass --------------------------------------


def test_xff_bypass_flagged_when_rotating_defeats_limit(monkeypatch):
    # Fixed XFF trips (429); rotating XFF never trips (200) -> bypass finding.
    def fake_request(method, url, *, cookie_header="", extra_headers=None, **k):
        xff = (extra_headers or {}).get("X-Forwarded-For", "")
        return Resp(status=429) if xff == rl._FIXED_XFF else Resp(status=200)

    monkeypatch.setattr(rl, "request", fake_request)
    findings = rl.probe_rate_limit_bypass(
        "https://t/api/login", "POST", "", attempts=5
    )
    assert len(findings) == 1
    assert findings[0].id == "rate-limit-bypass-forwarded-for"
    assert findings[0].severity == "high"


def test_xff_no_finding_when_rotating_also_throttles(monkeypatch):
    # Server keys on real IP: both bursts throttle -> no bypass.
    monkeypatch.setattr(rl, "request", lambda *a, **k: Resp(status=429))
    findings = rl.probe_rate_limit_bypass("https://t/api/login", "POST", "", attempts=5)
    assert findings == []


def test_xff_no_finding_when_no_limiter_exists(monkeypatch):
    # Fixed burst never throttles: nothing to bypass (missing-rate-limit's job).
    monkeypatch.setattr(rl, "request", lambda *a, **k: Resp(status=200))
    findings = rl.probe_rate_limit_bypass("https://t/api/login", "POST", "", attempts=5)
    assert findings == []


def test_xff_skips_non_auth_urls(monkeypatch):
    called = {"n": 0}

    def fake(*a, **k):
        called["n"] += 1
        return Resp(status=429)

    monkeypatch.setattr(rl, "request", fake)
    assert rl.probe_rate_limit_bypass("https://t/api/products", "GET", "") == []
    assert called["n"] == 0


def test_xff_ratelimit_header_counts_as_signal(monkeypatch):
    # A Retry-After on the rotating burst means the bypass did not work.
    def fake_request(method, url, *, cookie_header="", extra_headers=None, **k):
        xff = (extra_headers or {}).get("X-Forwarded-For", "")
        if xff == rl._FIXED_XFF:
            return Resp(status=200, headers={"retry-after": "5"})
        return Resp(status=200, headers={"retry-after": "5"})

    monkeypatch.setattr(rl, "request", fake_request)
    assert rl.probe_rate_limit_bypass("https://t/api/auth", "POST", "", attempts=5) == []


# --- unauthenticated exposure -----------------------------------------------


def test_unauth_exposure_flagged_on_sensitive_json(monkeypatch):
    monkeypatch.setattr(ue, "request", lambda *a, **k: Resp(status=200, body='[{"msg":"hi"}]'))
    findings = ue.probe_unauth_exposure("https://t/api/channels/123/messages", "GET")
    assert len(findings) == 1
    assert findings[0].id == "unauthenticated-data-exposure"
    assert findings[0].confidence == "probable"


def test_unauth_exposure_skips_auth_error_body(monkeypatch):
    monkeypatch.setattr(
        ue, "request",
        lambda *a, **k: Resp(status=200, body='{"detail":"Not authenticated"}'),
    )
    assert ue.probe_unauth_exposure("https://t/api/me", "GET") == []


def test_unauth_exposure_skips_spa_html_shell(monkeypatch):
    monkeypatch.setattr(
        ue, "request",
        lambda *a, **k: Resp(status=200, body="<!doctype html><html>", ctype="text/html"),
    )
    assert ue.probe_unauth_exposure("https://t/api/me", "GET") == []


def test_unauth_exposure_skips_non_sensitive_path(monkeypatch):
    called = {"n": 0}

    def fake(*a, **k):
        called["n"] += 1
        return Resp(status=200, body='{"ok":1}')

    monkeypatch.setattr(ue, "request", fake)
    assert ue.probe_unauth_exposure("https://t/api/docs/manifest", "GET") == []
    assert called["n"] == 0


def test_unauth_exposure_skips_401(monkeypatch):
    monkeypatch.setattr(ue, "request", lambda *a, **k: Resp(status=401, body='{"detail":"x"}'))
    assert ue.probe_unauth_exposure("https://t/api/me/saves", "GET") == []


def test_unauth_exposure_only_get(monkeypatch):
    called = {"n": 0}

    def fake(*a, **k):
        called["n"] += 1
        return Resp(status=200, body='{"ok":1}')

    monkeypatch.setattr(ue, "request", fake)
    assert ue.probe_unauth_exposure("https://t/api/me", "POST") == []
    assert called["n"] == 0
