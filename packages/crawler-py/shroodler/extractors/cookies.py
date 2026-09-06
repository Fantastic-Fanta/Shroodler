from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from shroodler.models import Cookie, Finding, Severity

# Names that look like session cookies (plus any name containing "session").
_SESSION_EXACT = frozenset(
    {
        "session",
        "sessionid",
        "session_id",
        "sessid",
        "sid",
        "phpsessid",
        "jsessionid",
        "aspsessionid",
        "asp.net_sessionid",
        "connect.sid",
        "auth",
        "authtoken",
        "auth_token",
    }
)


def parse_set_cookie(header: str) -> Cookie | None:
    parsed = _parse_set_cookie(header)
    return None if parsed is None else parsed[0]


def _parse_set_cookie(header: str) -> tuple[Cookie, str | None, str | None] | None:
    if not header or "=" not in header.split(";", 1)[0]:
        return None
    parts = [p.strip() for p in header.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    if not name:
        return None
    flags = {p.lower() for p in parts[1:] if "=" not in p}
    attrs: dict[str, str] = {}
    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            attrs[k.strip().lower()] = v.strip()
    same = attrs.get("samesite")
    if same:
        folded = same.lower()
        if folded == "strict":
            same_site = "Strict"
        elif folded == "lax":
            same_site = "Lax"
        elif folded == "none":
            same_site = "None"
        else:
            same_site = None
    else:
        same_site = None
    cookie = Cookie(
        name=name,
        secure="secure" in flags or "secure" in attrs,
        http_only="httponly" in flags or "httponly" in attrs,
        same_site=same_site,
    )
    path = attrs.get("path")
    domain = attrs.get("domain")
    return cookie, path, domain


def _session_base_name(name: str) -> str:
    if name.startswith("__Host-"):
        return name[len("__Host-") :]
    if name.startswith("__Secure-"):
        return name[len("__Secure-") :]
    return name


def is_session_cookie(name: str) -> bool:
    base = _session_base_name(name).lower()
    return base in _SESSION_EXACT or "session" in base


def _is_ip_host(host: str) -> bool:
    host = host.strip("[]")
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_loopback_or_local(host: str) -> bool:
    host = host.strip("[]").lower()
    if host in {"localhost", "localhost.localdomain"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def domain_is_broad(host: str, domain: str | None) -> bool:
    """True when Domain is a parent suffix of the host, or clearly too wide on loopback."""
    if not domain:
        return False
    domain = domain.strip().lstrip(".").lower()
    host = (host or "").strip("[]").lower()
    if not domain or not host:
        return False
    if _is_loopback_or_local(host) or _is_ip_host(host):
        return domain != host
    if host == domain:
        return False
    return host.endswith("." + domain)


def _finding(
    fid: str, severity: Severity, page_url: str, name: str, description: str
) -> Finding:
    return Finding(
        id=fid,
        severity=severity,
        category="cookie",
        url=page_url,
        description=description,
        evidence=name,
    )


def extract_cookies(
    set_cookie_headers: list[str], page_url: str, *, attrs_reliable: bool = True
) -> tuple[list[Cookie], list[Finding]]:
    """`attrs_reliable=False` is for headless mode, where the Set-Cookie
    "header" strings are actually SYNTHESIZED from the browser's cookie
    jar API (see modes/headless.py), which does not expose Path/Domain
    the way a real Set-Cookie header does -- Path/Domain are always
    absent in that reconstruction, regardless of what the real header
    said. Review caught that treating an absent Path/Domain as violation
    evidence under those conditions made EVERY __Host- cookie in a
    headless crawl false-positive (100% of the time, once per page),
    including ones a real browser demonstrably accepted and stored.
    With attrs_reliable=False, the Domain-presence and Path-exactness
    violation arms are skipped -- only the Secure flag (which the jar API
    *does* report reliably) is still checked.
    """
    cookies: list[Cookie] = []
    findings: list[Finding] = []
    parsed_url = urlparse(page_url)
    host = parsed_url.hostname or ""
    https = parsed_url.scheme.lower() == "https"
    # Browsers (Chrome's IsCookiePrefixValid, Firefox) also require
    # __Secure-/__Host- to be SET FROM a secure origin, not just carry
    # the Secure attribute -- treating loopback/localhost as trustworthy
    # even over plain HTTP, matching how real browsers special-case it
    # for local development.
    secure_origin = https or _is_loopback_or_local(host)
    for raw in set_cookie_headers:
        parsed = _parse_set_cookie(raw)
        if not parsed:
            continue
        cookie, path, domain = parsed
        cookies.append(cookie)
        path_norm = path.strip() if path is not None else None
        if path_norm == "":
            path_norm = "/"

        # __Secure-/__Host- are contracts a browser enforces at parse
        # time, not hardening advice: a Set-Cookie whose name carries
        # the prefix but doesn't meet the prefix's requirements is
        # REJECTED outright (RFC 6265bis s4.1.3) -- the app thinks it
        # set a cookie and it silently never existed. Deterministic
        # from the header alone (when attrs_reliable), independent of
        # whether this looks like a "session" cookie, and distinct from
        # cookie-missing-*-prefix below (a suggestion to adopt a prefix
        # that isn't there yet). Checked FIRST and, if violated, this is
        # the ONLY finding emitted for the cookie: every other
        # attribute-level check below (missing Secure/HttpOnly, broad
        # Path/Domain, ...) would otherwise describe a cookie that, per
        # this very finding, the browser never actually stored --
        # reporting both was reviewed as self-contradictory.
        prefix_violated = False
        if cookie.name.startswith("__Secure-") and (not cookie.secure or not secure_origin):
            reasons = []
            if not cookie.secure:
                reasons.append("is missing Secure")
            if not secure_origin:
                reasons.append("was set from a non-secure origin")
            findings.append(
                _finding(
                    "cookie-secure-prefix-violation",
                    "medium",
                    page_url,
                    cookie.name,
                    f"Cookie {cookie.name} uses the __Secure- prefix but "
                    f"{' and '.join(reasons)} -- browsers reject this Set-Cookie entirely, "
                    "so the application likely thinks it set a cookie that was never "
                    "actually stored",
                )
            )
            prefix_violated = True
        if cookie.name.startswith("__Host-"):
            violations = []
            if not cookie.secure:
                violations.append("is missing Secure")
            if not secure_origin:
                violations.append("was set from a non-secure origin")
            if attrs_reliable and domain:
                violations.append(f"has Domain={domain}")
            if attrs_reliable and path_norm != "/":
                # The __Host- prefix requires an EXPLICIT Path=/
                # attribute (RFC 6265bis), so an omitted Path
                # (path_norm is None) is itself a violation, not just
                # Path != "/".
                violations.append(f"has Path={path_norm or '(none)'} (must be /)")
            if violations:
                findings.append(
                    _finding(
                        "cookie-host-prefix-violation",
                        "medium",
                        page_url,
                        cookie.name,
                        f"Cookie {cookie.name} uses the __Host- prefix but "
                        f"{' and '.join(violations)} -- browsers reject this Set-Cookie "
                        "entirely, so the application likely thinks it set a cookie that "
                        "was never actually stored",
                    )
                )
                prefix_violated = True
        if prefix_violated:
            continue

        if not cookie.secure:
            findings.append(
                _finding(
                    "insecure-cookie",
                    "medium",
                    page_url,
                    cookie.name,
                    f"Cookie {cookie.name} is missing the Secure flag",
                )
            )
        if not cookie.http_only:
            findings.append(
                _finding(
                    "cookie-not-httponly",
                    "low",
                    page_url,
                    cookie.name,
                    f"Cookie {cookie.name} is missing HttpOnly",
                )
            )
        if cookie.same_site == "None" and not cookie.secure:
            findings.append(
                _finding(
                    "cookie-samesite-none-without-secure",
                    "medium",
                    page_url,
                    cookie.name,
                    f"Cookie {cookie.name} uses SameSite=None without Secure",
                )
            )
        session = is_session_cookie(cookie.name)
        # A __Host- cookie's Path=/ is mandatory (checked/enforced
        # above), not a broad-scope hardening problem -- flagging it
        # here too would tell the client to both set Path=/ (the prefix
        # requirement) and narrow it away from Path=/ (this suggestion)
        # for the same cookie.
        if session and path_norm == "/" and not cookie.name.startswith("__Host-"):
            findings.append(
                _finding(
                    "cookie-path-broad",
                    "info",
                    page_url,
                    cookie.name,
                    f"Session cookie {cookie.name} is scoped to Path=/",
                )
            )
        if domain_is_broad(host, domain):
            findings.append(
                _finding(
                    "cookie-domain-broad",
                    "low",
                    page_url,
                    cookie.name,
                    f"Cookie {cookie.name} Domain={domain} is broader than host {host}",
                )
            )
        if session and https and cookie.secure:
            has_host_prefix = cookie.name.startswith("__Host-")
            has_secure_prefix = has_host_prefix or cookie.name.startswith("__Secure-")
            no_domain = not domain
            if not has_host_prefix and no_domain and path_norm == "/":
                findings.append(
                    _finding(
                        "cookie-missing-host-prefix",
                        "info",
                        page_url,
                        cookie.name,
                        f"Session cookie {cookie.name} on HTTPS could use the __Host- prefix",
                    )
                )
            elif not has_secure_prefix:
                findings.append(
                    _finding(
                        "cookie-missing-secure-prefix",
                        "low",
                        page_url,
                        cookie.name,
                        f"Session cookie {cookie.name} on HTTPS could use the __Secure- prefix",
                    )
                )
    return cookies, findings
