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
        # RFC 7636 defaults code_challenge_method to "plain" when absent,
        # and "plain" sends the verifier itself as the challenge -- it
        # doesn't hide anything in transit/logs the way S256 does, so
        # only an explicit S256 challenge earns the full downgrade;
        # "plain" (or a present-but-unhashed challenge) is real PKCE
        # syntactically but weak enough that this stays at medium rather
        # than being treated as equivalent to a proper S256 challenge.
        code_challenge = _first(qs, "code_challenge")
        has_strong_pkce = code_challenge != "" and _first(qs, "code_challenge_method") == "S256"
        findings.append(
            _finding(
                "oauth-missing-state",
                # PKCE (code_challenge=S256) binds the authorization code
                # to the client that started the flow and is widely
                # considered adequate CSRF mitigation on its own in
                # modern implementations, so this is downgraded (not
                # dropped -- state alongside PKCE is still recommended
                # defense-in-depth per the OAuth Security BCP) rather
                # than treated as the same risk as no CSRF protection at
                # all.
                "low" if has_strong_pkce else "medium",
                url,
                (
                    "OAuth/OIDC authorization request has no state parameter, though "
                    "code_challenge=S256 (PKCE) is present -- PKCE mitigates most of the CSRF "
                    "risk state normally addresses, but state alongside it is still "
                    "recommended defense-in-depth"
                    if has_strong_pkce
                    else
                    "OAuth/OIDC authorization request has no state parameter and no S256 PKCE "
                    "challenge, which is what normally protects the redirect callback against "
                    "CSRF (an attacker tricking a victim into completing the attacker's own "
                    "OAuth flow)"
                    + (
                        " (a code_challenge is present but its method isn't S256, "
                        "which doesn't provide the same protection)"
                        if code_challenge
                        else ""
                    )
                ),
                url,
            )
        )

    # OIDC's hybrid flow allows a space-separated response_type
    # ("code token", "code id_token token", ...) -- any member being
    # "token" still returns an access token in the redirect fragment, so
    # exact string equality against the whole value would miss every
    # hybrid-flow variant and only catch the pure implicit-flow case.
    response_type = _first(qs, "response_type")
    if "token" in response_type.split():
        findings.append(
            _finding(
                "oauth-implicit-flow",
                "low",
                url,
                "OAuth response_type includes \"token\" (implicit or hybrid flow), which "
                "returns an access token directly in the redirect URI fragment, exposed to "
                "browser history/referrer leakage/redirector logs; OAuth 2.1 and current best "
                "practice deprecate this in favor of the authorization code flow (+ PKCE)",
                response_type,
            )
        )

    return findings
