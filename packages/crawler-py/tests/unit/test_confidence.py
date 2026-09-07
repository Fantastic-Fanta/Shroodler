from __future__ import annotations

from shroodler.confidence import confidence_for, stamp_findings
from shroodler.crawler import crawl_url
from shroodler.models import Finding
from shroodler.validate import validate_crawl


def test_header_absence_is_confirmed():
    assert confidence_for("missing-csp", "header") == "confirmed"
    assert confidence_for("missing-hsts", "header") == "confirmed"


def test_generic_api_key_is_heuristic():
    assert confidence_for("generic-api-key", "secret") == "heuristic"


def test_named_secret_falls_back_to_confirmed():
    assert confidence_for("aws-access-key", "secret") == "confirmed"


def test_idor_and_authz_are_probable():
    assert confidence_for("idor-adjacent-id-accessible", "auth") == "probable"
    assert confidence_for("authz-still-accessible", "auth") == "probable"


def test_auth_stack_fingerprint_is_heuristic():
    assert confidence_for("auth-stack-next-auth", "auth") == "heuristic"
    assert confidence_for("next-auth-callback-url-unvalidated", "auth") == "confirmed"


def test_stamp_skips_already_set_and_never_writes_null():
    findings = [
        {"id": "missing-csp", "category": "header"},
        {"id": "payload-xss-reflect", "category": "payload", "confidence": "confirmed"},
        {"id": "generic-api-key", "category": "secret", "confidence": None},
    ]
    stamp_findings(findings)
    assert findings[0]["confidence"] == "confirmed"
    assert findings[1]["confidence"] == "confirmed"
    assert findings[2]["confidence"] == "heuristic"
    assert all(f["confidence"] in {"confirmed", "probable", "heuristic"} for f in findings)


def test_crawl_json_stamps_confidence_and_validates(fx):
    fx.html("/", "<h1>home</h1>")
    doc = crawl_url(fx.origin + "/", depth=0, ignore_robots=True).to_dict()
    validate_crawl(doc)
    confs = {f["id"]: f.get("confidence") for f in doc["findings"]}
    assert confs
    assert None not in confs.values()
    assert "" not in confs.values()
    if "missing-csp" in confs:
        assert confs["missing-csp"] == "confirmed"


def test_finding_model_omits_unset_confidence_from_exclude_none():
    dumped = Finding(
        id="authz-still-accessible",
        severity="medium",
        category="auth",
        url="http://127.0.0.1/",
        description="x",
        evidence="e",
    ).model_dump(exclude_none=True)
    assert "confidence" not in dumped
