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


def _raw_query_is_well_formed(query: str) -> bool:
    """Reject a query string neither engine's stdlib parser can be
    trusted to agree on, rather than silently reasoning from a
    partially-parsed result.

    Verified in review: Go's net/url.Values (backed by url.ParseQuery)
    silently DROPS a pair whose value contains a bare ";" (rejected as an
    ambiguous separator since Go 1.17) or an invalid %-escape, discarding
    the error -- while Python's parse_qs is lenient and keeps the raw
    text unchanged. For "state=a;b" that made Go treat state as *absent*
    (a false oauth-missing-state on a URL that does carry a state value)
    while Python correctly saw "a;b". Rather than trying to make one
    stdlib parser's leniency match the other's exactly, both engines
    refuse to assess a query with either red flag at all.
    """
    if ";" in query:
        return False
    i = 0
    while True:
        i = query.find("%", i)
        if i == -1:
            return True
        hex_part = query[i + 1 : i + 3]
        if len(hex_part) != 2 or not all(c in "0123456789abcdefABCDEF" for c in hex_part):
            return False
        i += 3


def _parse_qs(url: str) -> dict[str, list[str]] | None:
    query = urlparse(url).query
    if not _raw_query_is_well_formed(query):
        return None
    # keep_blank_values=True + an explicit non-empty check below, rather
    # than relying on "key in qs" with the default keep_blank_values=False:
    # the default silently DROPS a blank occurrence of a repeated param
    # (?state=&state=real becomes {"state": ["real"]}, hiding the blank
    # first value entirely) instead of keeping it and reporting the first
    # one like Go's net/url.Values.Get does -- a real Python/Go parity
    # divergence caught in review, since the two engines would then
    # disagree on whether oauth-missing-state fires for that URL.
    return parse_qs(query, keep_blank_values=True)


def _first(qs: dict[str, list[str]], key: str) -> str:
    values = qs.get(key) or [""]
    return values[0]


def is_authorization_request(url: str) -> bool:
    qs = _parse_qs(url)
    if qs is None:
        return False
    return _first(qs, "response_type") != "" and _first(qs, "client_id") != ""


def check_oauth_authorize_url(url: str) -> list[Finding]:
    qs = _parse_qs(url)
    if qs is None:
        return []
    if _first(qs, "response_type") == "" or _first(qs, "client_id") == "":
        return []
    findings: list[Finding] = []

    # RFC 9101 (JAR) / RFC 9126 (PAR): response_type+client_id stay in
    # the query for OAuth2 compatibility even when the actual parameters
    # (including state) are carried inside a signed request object or
    # left server-side, referenced only by request/request_uri -- state
    # genuinely cannot be assessed passively here, and this is a MORE
    # secure deployment shape, not a less secure one. Reporting
    # oauth-missing-state against it would be a real overclaim.
    if _first(qs, "request") != "" or _first(qs, "request_uri") != "":
        return findings

    state = _first(qs, "state")
    if not state.strip():
        # RFC 7636 defaults code_challenge_method to "plain" when absent,
        # and "plain" sends the verifier itself as the challenge -- it
        # doesn't hide anything in transit/logs the way S256 does, so
        # only an explicit S256 challenge earns the full downgrade;
        # "plain" (or a present-but-unhashed challenge) is real PKCE
        # syntactically but weak enough that this stays at medium rather
        # than being treated as equivalent to a proper S256 challenge.
        code_challenge = _first(qs, "code_challenge").strip()
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
                # medium, not low: a token exposed in the URL fragment is
                # exploitable via history/referrer/redirector-log leakage
                # and turns any open redirect on the relying party into a
                # token-theft primitive; OAuth 2.1 removes this flow
                # outright rather than merely discouraging it.
                "medium",
                url,
                f"OAuth response_type={response_type!r} includes \"token\" (implicit or hybrid "
                "flow), which returns an access token directly in the redirect URI fragment, "
                "exposed to browser history/referrer leakage/redirector logs; OAuth 2.1 removes "
                "this flow in favor of the authorization code flow (+ PKCE)",
                url,
            )
        )

    return findings
