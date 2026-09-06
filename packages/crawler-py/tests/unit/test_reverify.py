from __future__ import annotations

from shroodler.reverify import reverify


def test_verified_fixed_when_finding_no_longer_present(fx):
    fx.on("GET", "/search", lambda inc: (200, {}, b"<html>no injection here</html>"))
    result = reverify(fx.origin + "/search", "payload-sql-error", run_payloads=False)
    assert result["verified_fixed"] is True
    assert result["still_present"] is False
    assert result["matching_findings"] == []


def test_still_present_when_finding_reappears(fx):
    fx.on(
        "GET",
        "/leak",
        lambda inc: (200, {"X-Powered-By": "PHP/5.2.1"}, b"ok"),
    )
    result = reverify(fx.origin + "/leak", "x-powered-by", run_payloads=False)
    assert result["still_present"] is True
    assert result["verified_fixed"] is False
    assert result["matching_findings"][0]["id"] == "x-powered-by"


def test_matches_only_the_same_url_path(fx):
    fx.on("GET", "/a", lambda inc: (200, {"X-Powered-By": "PHP"}, b"ok"))
    fx.on("GET", "/b", lambda inc: (200, {}, b"ok"))
    # Reverifying /b should not be confused by an unrelated finding at /a.
    result = reverify(fx.origin + "/b", "x-powered-by", run_payloads=False)
    assert result["verified_fixed"] is True
