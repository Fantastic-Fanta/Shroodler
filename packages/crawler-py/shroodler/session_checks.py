"""Session-hygiene checks that run around a --login-recipe authentication.

Two checks, both cheap add-ons to a crawl that already logs in:

- Session fixation: does the session cookie keep the same value across the
  login boundary? If so, an attacker who sets/knows the pre-auth session ID
  can hijack the session once the victim authenticates.
- Logout invalidation: if the recipe declares a logout_url, does the
  server-side session actually die on logout, or does replaying the old
  session cookie still work afterward?
"""

from __future__ import annotations

import httpx

from shroodler.extractors.cookies import is_session_cookie
from shroodler.models import Finding


def session_cookies(client: httpx.Client) -> dict[str, str]:
    return {name: value for name, value in dict(client.cookies).items() if is_session_cookie(name)}


def check_session_fixation(
    pre: dict[str, str],
    post: dict[str, str],
    url: str,
) -> list[Finding]:
    findings: list[Finding] = []
    for name, pre_value in pre.items():
        if not pre_value:
            continue
        post_value = post.get(name)
        if post_value == pre_value:
            findings.append(
                Finding(
                    id="session-fixation",
                    severity="high",
                    category="auth",
                    url=url,
                    description=(
                        f"Session cookie '{name}' kept the same value before and after "
                        "login -- the application does not appear to regenerate the "
                        "session identifier on authentication. An attacker who sets or "
                        "knows the pre-auth session ID can hijack the session once the "
                        "victim logs in."
                    ),
                    evidence=name,
                )
            )
    return findings


def check_logout_invalidation(
    *,
    logout_url: str,
    logout_method: str,
    protected_url: str,
    stale_cookie_header: str,
    timeout: float = 8.0,
) -> list[Finding]:
    if not stale_cookie_header:
        return []
    try:
        with httpx.Client(timeout=timeout, follow_redirects=False) as client:
            client.request(
                logout_method.upper(),
                logout_url,
                headers={"Cookie": stale_cookie_header},
            )
            check = client.get(protected_url, headers={"Cookie": stale_cookie_header})
    except httpx.HTTPError:
        return []

    if 200 <= check.status_code < 300:
        return [
            Finding(
                id="logout-session-not-invalidated",
                severity="high",
                category="auth",
                url=protected_url,
                description=(
                    f"Replaying the pre-logout session cookie against {protected_url} "
                    f"after logging out still succeeded (status {check.status_code}) -- "
                    "the server-side session was not invalidated on logout, so a stolen "
                    "session cookie stays usable even after the legitimate user logs out."
                ),
                evidence=f"status={check.status_code}",
            )
        ]
    return []
