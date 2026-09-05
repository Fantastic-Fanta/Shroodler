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


def _parse_qs(url: str) -> dict[str, list[str]]:
    # keep_blank_values=True + an explicit non-empty check below, rather
    # than relying on "key in qs" with the default keep_blank_values=False:
    # the default silently DROPS a blank occurrence of a repeated param
    # (?state=&state=real becomes {"state": ["real"]}, hiding the blank
    # first value entirely) instead of keeping it and reporting the first
    # one like Go's net/url.Values.Get does -- a real Python/Go parity
    # divergence caught in review, since the two engines would then
    # disagree on whether oauth-missing-state fires for that URL.
    return parse_qs(urlparse(url).query, keep_blank_values=True)


def _first(qs: dict[str, list[str]], key: str) -> str:
    values = qs.get(key) or [""]
    return values[0]


def is_authorization_request(url: str) -> bool:
    qs = _parse_qs(url)
    return _first(qs, "response_type") != "" and _first(qs, "client_id") != ""


def check_oauth_authorize_url(url: str) -> list[Finding]:
    if not is_authorization_request(url):
        return []
    qs = _parse_qs(url)
    findings: list[Finding] = []

    state = _first(qs, "state")
    if not state.strip():
        has_pkce = _first(qs, "code_challenge") != ""
        findings.append(
            _finding(
                "oauth-missing-state",
                # PKCE (code_challenge) binds the authorization code to
                # the client that started the flow and is widely
                # considered adequate CSRF mitigation on its own in
                # modern implementations, so this is downgraded (not
                # dropped -- state alongside PKCE is still recommended
                # defense-in-depth per the OAuth Security BCP) rather
                # than treated as the same risk as no CSRF protection at
                # all.
                "low" if has_pkce else "medium",
                url,
                (
                    "OAuth/OIDC authorization request has no state parameter, though "
                    "code_challenge (PKCE) is present -- PKCE mitigates most of the CSRF "
                    "risk state normally addresses, but state alongside it is still "
                    "recommended defense-in-depth"
                    if has_pkce
                    else
                    "OAuth/OIDC authorization request has no state parameter and no PKCE "
                    "(code_challenge), which is what normally protects the redirect callback "
                    "against CSRF (an attacker tricking a victim into completing the "
                    "attacker's own OAuth flow)"
                ),
                url,
            )
        )

    response_type = _first(qs, "response_type")
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
