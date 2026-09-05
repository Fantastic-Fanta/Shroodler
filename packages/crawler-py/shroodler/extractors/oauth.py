"""OAuth 2.0 / OIDC authorization-request checks.

Purely passive: inspects a crawled URL's own query string, no extra
requests. An "authorization request" is identified per RFC 6749 s4.1.1 by
the presence of both `response_type` and `client_id` -- those two are the
spec-required parameters for exactly this request type, so there's no
ambiguity/false-positive risk in deciding whether a URL *is* one; the
checks below are then simple presence/value checks on well-defined
parameters, not heuristics.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

from shroodler.models import Finding


def _finding(fid: str, severity: str, url: str, description: str, evidence: str) -> Finding:
    return Finding(
        id=fid,
        severity=severity,
        category="auth",
        url=url,
        description=description,
        evidence=evidence,
    )


def is_authorization_request(url: str) -> bool:
    qs = parse_qs(urlparse(url).query)
    return "response_type" in qs and "client_id" in qs


def check_oauth_authorize_url(url: str) -> list[Finding]:
    if not is_authorization_request(url):
        return []
    qs = parse_qs(urlparse(url).query)
    findings: list[Finding] = []

    state = qs.get("state", [""])[0]
    if not state.strip():
        findings.append(
            _finding(
                "oauth-missing-state",
                "medium",
                url,
                "OAuth/OIDC authorization request has no state parameter, which is what "
                "normally protects the redirect callback against CSRF (an attacker tricking "
                "a victim into completing the attacker's own OAuth flow)",
                url,
            )
        )

    response_type = qs.get("response_type", [""])[0]
    if response_type == "token":
        findings.append(
            _finding(
                "oauth-implicit-flow",
                "low",
                url,
                "OAuth response_type=token (implicit flow) returns the access token "
                "directly in the redirect URI fragment, exposed to browser history/referrer "
                "leakage/redirector logs; OAuth 2.1 and current best practice deprecate it in "
                "favor of the authorization code flow (+ PKCE)",
                response_type,
            )
        )

    return findings
