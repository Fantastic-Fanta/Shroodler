"""Confidence classification for crawl-time (passive) findings.

Payload tester already stamps `confirmed` / `probable` / `heuristic` from
which match clause fired. Crawl JSON historically left the field unset,
so HTML/MD/CSV reports showed an empty Confidence column for almost
every finding. This fills that gap with a conservative id-then-category
lookup — the same shape as cost-of-attack / remediation.

Tiers:
- confirmed: an exact, unambiguous observation (header absent, cookie
  flag missing, named secret regex hit, TLS handshake result).
- probable: a strong-but-inferential lead (IDOR adjacent-id, authz
  without an identity marker).
- heuristic: a fingerprint or noisy signal (generic-api-key entropy,
  auth-stack cookie/path match, HTML comments, JS-extracted endpoints).
"""

from __future__ import annotations

Confidence = str  # "confirmed" | "probable" | "heuristic"

_BY_ID: dict[str, str] = {
    "generic-api-key": "heuristic",
    "auth-stack-next-auth": "heuristic",
    "auth-stack-keycloak": "heuristic",
    "auth-stack-auth0": "heuristic",
    "oauth-redirect-uri-unvalidated": "confirmed",
    "next-auth-callback-url-unvalidated": "confirmed",
    "idor-adjacent-id-accessible": "probable",
    "authz-still-accessible": "probable",
    "authz-broken-access-control": "probable",
    "rate-limit-bypass-forwarded-for": "confirmed",
    "unauthenticated-data-exposure": "probable",
    "guessable-capability-id": "heuristic",
    "peer-write-idor": "probable",
    "csrf-state-change-unprotected": "probable",
    "chain-xss-cookie-theft": "probable",
    "chain-cors-credentialed": "probable",
    "payload-xss-stored": "confirmed",
    "sqli-auth-bypass": "confirmed",
    "xss-reflected-nonhtml": "heuristic",
    "xss-stored-nonhtml": "heuristic",
    "graphql-field-authz": "probable",
    "js-jsonrpc-method": "heuristic",
    "js-trpc-procedure": "heuristic",
    "js-react-query-key": "heuristic",
    "js-graphql-operation": "heuristic",
    "html-comment": "heuristic",
    "meta-generator": "heuristic",
    "js-endpoint": "heuristic",
    "ghost-route": "heuristic",
    "verbose-error": "heuristic",
    "graphql-probe-skipped": "heuristic",
    "cors-probe-skipped": "heuristic",
    "session-checks-skipped-headless": "heuristic",
    "session-reauthenticated": "confirmed",
    "session-died": "confirmed",
    "redirect-chain-truncated": "heuristic",
    "off-origin-redirect-not-followed": "heuristic",
    "robots-blocked-crawl": "heuristic",
}

_BY_CATEGORY: dict[str, str] = {
    "header": "confirmed",
    "cookie": "confirmed",
    "tls": "confirmed",
    "secret": "confirmed",
    "exposed-file": "confirmed",
    "autocomplete": "confirmed",
    "waf-challenge": "confirmed",
    "subresource": "confirmed",
    "auth": "probable",
    "js-endpoint": "heuristic",
    "verbose-error": "heuristic",
    "scan-note": "heuristic",
    "payload": "heuristic",
    "smart-contract": "probable",
    "sast": "probable",
}

_DEFAULT = "heuristic"


def confidence_for(finding_id: str, category: str = "") -> str:
    if finding_id in _BY_ID:
        return _BY_ID[finding_id]
    if category in _BY_CATEGORY:
        return _BY_CATEGORY[category]
    return _DEFAULT


def stamp_findings(findings: list[dict]) -> None:
    """Fill missing `confidence` in place. Never writes null — the schema
    enum has no null, and reports treat a missing/empty cell as "unset".
    An already-stamped value (payload tester, authz identity marker) wins.
    """
    for f in findings:
        existing = f.get("confidence")
        if existing in {"confirmed", "probable", "heuristic"}:
            continue
        f["confidence"] = confidence_for(f.get("id") or "", f.get("category") or "")
