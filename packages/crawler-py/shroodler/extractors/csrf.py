"""Authenticated CSRF: cookie session + state-changing form, no token.

Only fires when a session cookie is SameSite=None (cross-site POSTs still
send it) and a POST/PUT/PATCH/DELETE form on that origin has no CSRF
field. Lax/default cookies are not flagged — modern browsers already
withhold those on cross-site POSTs.
"""

from __future__ import annotations

from shroodler.csrf import is_csrf_field_name
from shroodler.extractors.cookies import is_session_cookie
from shroodler.models import Finding, Page
from shroodler.urls import origin as origin_of


def csrf_findings(pages: list[Page]) -> list[Finding]:
    by_origin: dict[str, list[Page]] = {}
    for page in pages:
        by_origin.setdefault(origin_of(page.url), []).append(page)

    out: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for origin, group in by_origin.items():
        none_cookies = []
        for page in group:
            for cookie in page.cookies:
                if cookie.same_site == "None" and is_session_cookie(cookie.name):
                    none_cookies.append(cookie.name)
        if not none_cookies:
            continue
        cookie_note = ", ".join(sorted(set(none_cookies)))
        for page in group:
            for form in page.forms:
                method = (form.method or "GET").upper()
                if method not in {"POST", "PUT", "PATCH", "DELETE"}:
                    continue
                if any(is_csrf_field_name(f.name) for f in form.fields):
                    continue
                action = form.action or page.url
                key = (action, method)
                if key in seen:
                    continue
                seen.add(key)
                out.append(
                    Finding(
                        id="csrf-state-change-unprotected",
                        severity="medium",
                        category="auth",
                        url=page.url,
                        description=(
                            f"{method} {action} is a state-changing form with no CSRF "
                            f"token, and session cookie(s) {cookie_note} use "
                            "SameSite=None so a third-party origin can include them "
                            "on a cross-site POST. Confirm the endpoint also lacks "
                            "an Origin/Referer allowlist before reporting."
                        ),
                        evidence=f"cookies={cookie_note} method={method}",
                    )
                )
    return out
