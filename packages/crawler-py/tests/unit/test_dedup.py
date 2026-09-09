from __future__ import annotations

from shroodler.dedup import deduplicate
from shroodler.models import Finding


def test_same_param_keeps_highest_confidence():
    findings = [
        {
            "id": "xss-reflected",
            "severity": "high",
            "category": "payload",
            "url": "http://127.0.0.1/search",
            "description": "a",
            "evidence": "param=q nonce=1",
            "confidence": "heuristic",
        },
        {
            "id": "xss-reflected",
            "severity": "high",
            "category": "payload",
            "url": "http://127.0.0.1/search",
            "description": "b",
            "evidence": "param=q nonce=2",
            "confidence": "confirmed",
        },
    ]
    out = deduplicate(findings)
    assert len(out) == 1
    assert out[0]["confidence"] == "confirmed"
    assert out[0]["description"] == "b"


def test_different_params_are_kept():
    findings = [
        {
            "id": "xss-reflected",
            "severity": "high",
            "category": "payload",
            "url": "http://127.0.0.1/search",
            "description": "q",
            "evidence": "param=q",
            "confidence": "confirmed",
        },
        {
            "id": "xss-reflected",
            "severity": "high",
            "category": "payload",
            "url": "http://127.0.0.1/search",
            "description": "name",
            "evidence": "param=name",
            "confidence": "confirmed",
        },
    ]
    assert len(deduplicate(findings)) == 2


def test_host_level_one_per_origin():
    findings = [
        {
            "id": "missing-csp",
            "severity": "medium",
            "category": "header",
            "url": "https://example.com/a",
            "description": "a",
            "evidence": None,
            "confidence": "heuristic",
        },
        {
            "id": "missing-csp",
            "severity": "medium",
            "category": "header",
            "url": "https://example.com/b",
            "description": "b",
            "evidence": None,
            "confidence": "confirmed",
        },
        {
            "id": "tls-cert-expired",
            "severity": "high",
            "category": "tls",
            "url": "https://example.com/",
            "description": "tls",
            "evidence": None,
            "confidence": "confirmed",
        },
    ]
    out = deduplicate(findings)
    csp = [f for f in out if f["id"] == "missing-csp"]
    assert len(csp) == 1
    assert csp[0]["confidence"] == "confirmed"
    assert any(f["id"] == "tls-cert-expired" for f in out)


def test_operational_keep_first():
    findings = [
        {
            "id": "session-reauthenticated",
            "severity": "info",
            "category": "scan-note",
            "url": "http://127.0.0.1/a",
            "description": "first",
            "evidence": None,
            "confidence": "confirmed",
        },
        {
            "id": "session-reauthenticated",
            "severity": "info",
            "category": "scan-note",
            "url": "http://127.0.0.1/b",
            "description": "second",
            "evidence": None,
            "confidence": "confirmed",
        },
    ]
    out = deduplicate(findings)
    assert len(out) == 1
    assert out[0]["description"] == "first"


def test_accepts_finding_models():
    findings = [
        Finding(
            id="xss-reflected",
            severity="high",
            category="payload",
            url="http://127.0.0.1/x",
            description="a",
            evidence="param=q",
            confidence="probable",
        ),
        Finding(
            id="xss-reflected",
            severity="high",
            category="payload",
            url="http://127.0.0.1/x",
            description="b",
            evidence="param=q",
            confidence="confirmed",
        ),
    ]
    out = deduplicate(findings)
    assert len(out) == 1
    assert out[0]["confidence"] == "confirmed"
