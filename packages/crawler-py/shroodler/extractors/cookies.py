from __future__ import annotations

from shroodler.models import Cookie, Finding


def parse_set_cookie(header: str) -> Cookie | None:
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
    return Cookie(
        name=name,
        secure="secure" in flags or "secure" in attrs,
        http_only="httponly" in flags or "httponly" in attrs,
        same_site=same_site,
    )


def extract_cookies(
    set_cookie_headers: list[str], page_url: str
) -> tuple[list[Cookie], list[Finding]]:
    cookies: list[Cookie] = []
    findings: list[Finding] = []
    for raw in set_cookie_headers:
        cookie = parse_set_cookie(raw)
        if not cookie:
            continue
        cookies.append(cookie)
        if not cookie.secure:
            findings.append(
                Finding(
                    id="insecure-cookie",
                    severity="medium",
                    category="cookie",
                    url=page_url,
                    description=f"Cookie {cookie.name} is missing the Secure flag",
                    evidence=cookie.name,
                )
            )
        if not cookie.http_only:
            findings.append(
                Finding(
                    id="cookie-not-httponly",
                    severity="low",
                    category="cookie",
                    url=page_url,
                    description=f"Cookie {cookie.name} is missing HttpOnly",
                    evidence=cookie.name,
                )
            )
        if cookie.same_site == "None" and not cookie.secure:
            findings.append(
                Finding(
                    id="cookie-samesite-none-without-secure",
                    severity="medium",
                    category="cookie",
                    url=page_url,
                    description=f"Cookie {cookie.name} uses SameSite=None without Secure",
                    evidence=cookie.name,
                )
            )
    return cookies, findings
