"""Auth-stack fingerprinting and a small library of known-pattern probes.

Detects common auth stacks from cookie/path signatures (next-auth first,
then Keycloak/Auth0 as fingerprint-only) and, for next-auth, runs the
callbackUrl-into-cookie check that previously had to be reconstructed by
hand each time. Passive fingerprint findings are info; a confirmed
unvalidated callback URL is medium.

Probes are extra GETs, gated by the same local-only / --allow-external
posture as CORS/GraphQL. One round per origin, not per page.
"""

from __future__ import annotations

from urllib.parse import urljoin

from shroodler.models import Finding
from shroodler.urls import is_loopback_or_local

CALLBACK_MARKER = "https://shroodler.invalid/next-auth-callback"

_NEXT_AUTH_COOKIE_NEEDLES = (
    "next-auth.session-token",
    "next-auth.callback-url",
    "next-auth.csrf-token",
    "next-auth.pkce.code_verifier",
)
_KEYCLOAK_COOKIE_NEEDLES = ("auth_session_id", "kc_restart", "keycloak")
_AUTH0_COOKIE_NEEDLES = ("auth0", "did_compat", "a0:state")


def _cookie_names(pages) -> list[str]:
    names: list[str] = []
    for page in pages:
        for cookie in getattr(page, "cookies", []) or []:
            names.append(cookie.name)
    return names


def _has_next_auth(names: list[str], pages) -> bool:
    lowered = [n.lower() for n in names]
    if any(any(needle in n for needle in _NEXT_AUTH_COOKIE_NEEDLES) for n in lowered):
        return True
    return any("/api/auth/" in (getattr(p, "url", "") or "") for p in pages)


def _has_keycloak(names: list[str], pages) -> bool:
    lowered = [n.lower() for n in names]
    if any(any(needle in n for needle in _KEYCLOAK_COOKIE_NEEDLES) for n in lowered):
        return True
    return any("/realms/" in (getattr(p, "url", "") or "") for p in pages)


def _has_auth0(names: list[str], pages) -> bool:
    lowered = [n.lower() for n in names]
    if any(any(needle in n for needle in _AUTH0_COOKIE_NEEDLES) for n in lowered):
        return True
    return any("auth0.com" in (getattr(p, "url", "") or "") for p in pages)


def probe_auth_stack(
    origin: str,
    http,
    pages,
    *,
    allow_external: bool = False,
) -> list[Finding]:
    if not is_loopback_or_local(origin) and not allow_external:
        return []
    names = _cookie_names(pages)
    findings: list[Finding] = []
    if _has_next_auth(names, pages):
        findings.extend(_probe_next_auth(origin, http, names))
    if _has_keycloak(names, pages):
        findings.append(
            Finding(
                id="auth-stack-keycloak",
                severity="info",
                category="auth",
                url=origin,
                description=(
                    "Keycloak cookie/path signature observed. Known-pattern "
                    "probes for this stack are not wired yet -- fingerprint only."
                ),
                evidence=",".join(n for n in names if "keycloak" in n.lower() or "kc_" in n.lower())
                or "/realms/",
            )
        )
    if _has_auth0(names, pages):
        findings.append(
            Finding(
                id="auth-stack-auth0",
                severity="info",
                category="auth",
                url=origin,
                description=(
                    "Auth0 cookie/host signature observed. Known-pattern "
                    "probes for this stack are not wired yet -- fingerprint only."
                ),
                evidence=",".join(n for n in names if "auth0" in n.lower()) or "auth0.com",
            )
        )
    return findings


def _probe_next_auth(origin: str, http, names: list[str]) -> list[Finding]:
    findings = [
        Finding(
            id="auth-stack-next-auth",
            severity="info",
            category="auth",
            url=urljoin(origin.rstrip("/") + "/", "api/auth/providers"),
            description=(
                "next-auth cookie/path signature observed. Running the "
                "callbackUrl-into-cookie probe against /api/auth/signin."
            ),
            evidence=",".join(n for n in names if "next-auth" in n.lower()) or "/api/auth/",
        )
    ]
    providers = http.fetch(urljoin(origin.rstrip("/") + "/", "api/auth/providers"))
    if providers.status_code == 200 and providers.text.lstrip().startswith("{"):
        findings[0] = findings[0].model_copy(
            update={"evidence": (findings[0].evidence or "") + " providers=json"}
        )
    probe_url = urljoin(origin.rstrip("/") + "/", "api/auth/signin")
    probe_url = probe_url + "?callbackUrl=" + CALLBACK_MARKER
    resp = http.fetch(probe_url)
    cookies = " ".join(resp.set_cookies or [])
    if CALLBACK_MARKER in cookies or CALLBACK_MARKER in (resp.headers.get("set-cookie") or ""):
        findings.append(
            Finding(
                id="next-auth-callback-url-unvalidated",
                severity="medium",
                category="auth",
                url=probe_url,
                description=(
                    "next-auth accepted an unvalidated callbackUrl into the "
                    "callback-url cookie. An attacker-controlled URL here is "
                    "the open-redirect/login-csrf primitive this stack is "
                    "known for -- confirm whether the cookie is later used "
                    "as a post-login redirect without an allowlist."
                ),
                evidence="callback-url cookie echoed " + CALLBACK_MARKER,
            )
        )
    return findings
