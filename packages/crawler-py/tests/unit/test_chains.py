from __future__ import annotations

from shroodler.chains import chain_findings, collapse_systemic_findings
from shroodler.models import Cookie, Finding, Page


def test_chain_xss_and_missing_httponly():
    findings = [
        Finding(
            id="payload-xss-reflect",
            severity="medium",
            category="payload",
            url="http://127.0.0.1/search",
            description="xss",
        )
    ]
    pages = [
        Page(
            url="http://127.0.0.1/search",
            status_code=200,
            cookies=[Cookie(name="sessionid", secure=True, http_only=False, same_site="Lax")],
        )
    ]
    chains = chain_findings(findings, pages)
    assert [c.id for c in chains] == ["chain-xss-cookie-theft"]


def test_chain_cors_and_samesite_none():
    findings = [
        Finding(
            id="cors-reflect-origin",
            severity="medium",
            category="header",
            url="http://127.0.0.1/api",
            description="cors",
        )
    ]
    pages = [
        Page(
            url="http://127.0.0.1/api",
            status_code=200,
            cookies=[Cookie(name="sessionid", secure=True, http_only=True, same_site="None")],
        )
    ]
    chains = chain_findings(findings, pages)
    assert [c.id for c in chains] == ["chain-cors-credentialed"]


def test_collapse_header_repeats():
    rows = [
        {
            "id": "missing-csp",
            "category": "header",
            "url": f"http://127.0.0.1/p{i}",
            "description": "no csp",
            "severity": "low",
        }
        for i in range(10)
    ]
    rows.append(
        {
            "id": "payload-xss-reflect",
            "category": "payload",
            "url": "http://127.0.0.1/search",
            "description": "xss",
            "severity": "medium",
        }
    )
    out = collapse_systemic_findings(rows, min_count=8)
    ids = [r["id"] for r in out]
    assert ids.count("missing-csp") == 1
    assert "clustered" in (out[0].get("evidence") or "")
    assert ids.count("payload-xss-reflect") == 1
