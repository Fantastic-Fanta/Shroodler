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
            severity="high",
            category="header",
            url="http://127.0.0.1/api",
            description="cors",
            evidence="Origin: https://evil.example → ACAO=https://evil.example ACAC=true",
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


def test_chain_cors_wildcard_without_credentials_does_not_fire():
    findings = [
        Finding(
            id="cors-allow-any",
            severity="info",
            category="header",
            url="http://127.0.0.1/api",
            description="*",
        )
    ]
    pages = [
        Page(
            url="http://127.0.0.1/api",
            status_code=200,
            cookies=[Cookie(name="sessionid", secure=True, http_only=True, same_site="None")],
        )
    ]
    assert chain_findings(findings, pages) == []


def test_chain_xss_ignores_non_session_cookie_not_httponly():
    findings = [
        Finding(
            id="payload-xss-reflect",
            severity="medium",
            category="payload",
            url="http://127.0.0.1/search",
            description="xss",
        ),
        Finding(
            id="cookie-not-httponly",
            severity="low",
            category="cookie",
            url="http://127.0.0.1/search",
            description="locale",
        ),
    ]
    pages = [
        Page(
            url="http://127.0.0.1/search",
            status_code=200,
            cookies=[Cookie(name="locale", secure=False, http_only=False, same_site="Lax")],
        )
    ]
    assert chain_findings(findings, pages) == []


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


def test_collapse_keeps_highest_severity():
    rows = [
        {
            "id": "cors-reflect-origin",
            "category": "header",
            "url": f"http://127.0.0.1/p{i}",
            "description": "cors",
            "severity": "info",
            "evidence": "ACAO=*",
        }
        for i in range(8)
    ]
    rows.append(
        {
            "id": "cors-reflect-origin",
            "category": "header",
            "url": "http://127.0.0.1/api",
            "description": "cors creds",
            "severity": "high",
            "evidence": "ACAC=true",
        }
    )
    out = collapse_systemic_findings(rows, min_count=8)
    cors = [r for r in out if r["id"] == "cors-reflect-origin"]
    assert len(cors) == 1
    assert cors[0]["severity"] == "high"
    assert "ACAC=true" in (cors[0].get("evidence") or "")
