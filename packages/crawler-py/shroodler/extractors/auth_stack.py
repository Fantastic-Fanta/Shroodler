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

import re
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

from shroodler.extractors.oauth import is_authorization_request
from shroodler.models import Finding
from shroodler.urls import is_loopback_or_local, same_origin
from shroodler.urls import origin as origin_of

CALLBACK_MARKER = "https://shroodler.invalid/next-auth-callback"
OAUTH_REDIRECT_MARKER = "https://shroodler.invalid/oauth-callback"
MAX_REDIRECT_PROBES = 8
_REALM_PATH = re.compile(r"/realms/([A-Za-z0-9._-]{1,64})/")

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
    return any(
        "auth0.com" in ((urlparse(getattr(p, "url", "") or "").hostname or "").lower())
        for p in pages
    )


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
    has_kc = _has_keycloak(names, pages)
    has_a0 = _has_auth0(names, pages)
    if _has_next_auth(names, pages):
        findings.extend(_probe_next_auth(origin, http, names))
    if has_kc:
        findings.append(
            Finding(
                id="auth-stack-keycloak",
                severity="info",
                category="auth",
                url=origin,
                description=(
                    "Keycloak cookie/path signature observed. Probing "
                    "redirect_uri allowlisting on on-origin authorize endpoints."
                ),
                evidence=",".join(n for n in names if "keycloak" in n.lower() or "kc_" in n.lower())
                or "/realms/",
            )
        )
    if has_a0:
        findings.append(
            Finding(
                id="auth-stack-auth0",
                severity="info",
                category="auth",
                url=origin,
                description=(
                    "Auth0 cookie/host signature observed. Probing redirect_uri "
                    "allowlisting on on-origin authorize endpoints."
                ),
                evidence=",".join(n for n in names if "auth0" in n.lower()) or "auth0.com",
            )
        )
    findings.extend(
        probe_redirect_uri_allowlist(
            origin,
            http,
            pages,
            keycloak=has_kc,
            auth0=has_a0,
            allow_external=allow_external,
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


def _with_attacker_redirect(url: str) -> str | None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return None
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs["redirect_uri"] = [OAUTH_REDIRECT_MARKER]
    if not qs.get("response_type"):
        qs["response_type"] = ["code"]
    if not qs.get("client_id"):
        qs["client_id"] = ["account"]
    query = urlencode({k: v[-1] if v else "" for k, v in qs.items()})
    return urlunparse(parsed._replace(query=query, fragment=""))


def _redirects_to_attacker(resp) -> bool:
    status = int(getattr(resp, "status_code", 0) or 0)
    if status not in {301, 302, 303, 307, 308}:
        return False
    loc = getattr(resp, "redirect_to", None) or ""
    headers = getattr(resp, "headers", None) or {}
    if not loc:
        for k, v in headers.items():
            if str(k).lower() == "location":
                loc = str(v)
                break
    if not loc:
        return False
    parsed = urlparse(loc.strip())
    marker = urlparse(OAUTH_REDIRECT_MARKER)
    return (
        parsed.scheme == marker.scheme
        and (parsed.hostname or "").lower() == (marker.hostname or "").lower()
        and (parsed.path or "/") == (marker.path or "/")
    )


def _form_posts_to_attacker(resp) -> bool:
    """response_mode=form_post: 200 HTML whose form action is the marker URL."""
    status = int(getattr(resp, "status_code", 0) or 0)
    if status != 200:
        return False
    text = getattr(resp, "text", None) or ""
    if "<form" not in text.lower():
        return False
    from bs4 import BeautifulSoup

    marker = urlparse(OAUTH_REDIRECT_MARKER)
    soup = BeautifulSoup(text, "lxml")
    for form in soup.find_all("form"):
        action = (form.get("action") or "").strip()
        if not action:
            continue
        parsed = urlparse(action)
        if (
            parsed.scheme == marker.scheme
            and (parsed.hostname or "").lower() == (marker.hostname or "").lower()
            and (parsed.path or "/") == (marker.path or "/")
        ):
            return True
    return False


def probe_redirect_uri_allowlist(
    origin: str,
    http,
    pages,
    *,
    keycloak: bool = False,
    auth0: bool = False,
    allow_external: bool = False,
) -> list[Finding]:
    """Swap redirect_uri to an attacker URL on on-origin authorize endpoints.

    Gated like CORS: same-origin only, local-only unless --allow-external.
    Does not follow the redirect (no request to the attacker host).
    """
    if not is_loopback_or_local(origin) and not allow_external:
        return []
    candidates: list[str] = []
    seen: set[str] = set()

    def add(url: str) -> None:
        if not url or url in seen or not same_origin(url, origin):
            return
        seen.add(url)
        candidates.append(url)

    for page in pages:
        url = getattr(page, "url", "") or ""
        if is_authorization_request(url):
            add(url)
    if keycloak:
        realms: set[str] = set()
        for page in pages:
            url = getattr(page, "url", "") or ""
            path = urlparse(url).path or ""
            for match in _REALM_PATH.finditer(path):
                realm = match.group(1)
                if realm and realm[0].isalnum() and "/" not in realm and ".." not in realm:
                    realms.add(realm)
        for realm in sorted(realms)[:4]:
            add(
                urljoin(
                    origin_of(origin).rstrip("/") + "/",
                    f"realms/{realm}/protocol/openid-connect/auth",
                )
            )
    if auth0:
        add(urljoin(origin_of(origin).rstrip("/") + "/", "authorize"))

    findings: list[Finding] = []
    n = 0
    for url in candidates:
        if n >= MAX_REDIRECT_PROBES:
            break
        probe = _with_attacker_redirect(url)
        if not probe or not same_origin(probe, origin):
            continue
        n += 1
        try:
            resp = http.request("GET", probe, anonymous=True)
        except TypeError:
            continue
        if not _redirects_to_attacker(resp) and not _form_posts_to_attacker(resp):
            continue
        findings.append(
            Finding(
                id="oauth-redirect-uri-unvalidated",
                severity="high",
                category="auth",
                url=probe,
                description=(
                    "Authorization endpoint accepted redirect_uri="
                    f"{OAUTH_REDIRECT_MARKER} and sent the client there. "
                    "The callback allowlist is missing or too broad — this is "
                    "an open redirect on the OAuth code/token response."
                ),
                evidence=f"redirect_uri={OAUTH_REDIRECT_MARKER}",
            )
        )
    return findings
