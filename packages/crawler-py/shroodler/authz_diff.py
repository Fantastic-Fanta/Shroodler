"""authz-diff: replay a privileged crawl's pages under a second session.

Consumes a crawl JSON produced against one session (e.g. an admin account,
via `shroodler crawl --cookie ...`) and re-requests every page URL in it
using a second, lower-privileged session's cookies/headers. A URL that the
lower-privileged session can still reach is a broken-access-control / IDOR
candidate -- especially when an anonymous (no-session) control request to
the same URL is rejected, which confirms the endpoint was actually meant
to require a *specific* session, not just *any* session.

This is a replay tool, not a crawler: it does not discover new URLs, it
only re-requests URLs the privileged crawl already found.
"""

from __future__ import annotations

import httpx

from shroodler.models import Finding
from shroodler.urls import is_loopback_or_local


def _is_success(status: int) -> bool:
    return 200 <= status < 300


_LOGIN_REDIRECT_HINTS = ("login", "signin", "sign-in", "log-in", "auth", "session/new")


def _is_denied(status: int, location: str = "") -> bool:
    """A response counts as "denied" only when it's an explicit 401/403, or
    a redirect that specifically looks like a bounce to a login/auth page.

    A bare 3xx is NOT enough on its own -- ordinary trailing-slash, HTTPS
    upgrade, or locale redirects are common on pages that have nothing to
    do with authorization, and treating every redirect as a denial turns
    the anonymous control probe into a false-positive generator.
    """
    if status in (401, 403):
        return True
    if status in (301, 302, 303, 307, 308):
        loc = location.lower()
        return any(hint in loc for hint in _LOGIN_REDIRECT_HINTS)
    return False


def run(
    higher_doc: dict,
    *,
    cookie_header: str = "",
    extra_headers: dict[str, str] | None = None,
    check_anonymous: bool = True,
    allow_external: bool = False,
    client: httpx.Client | None = None,
) -> dict:
    target = higher_doc.get("target", "")
    if not allow_external and not is_loopback_or_local(target):
        raise ValueError(
            "authz-diff refuses non-local targets without --allow-external "
            "(only scan hosts you are authorized to test)"
        )
    http = client or httpx.Client(timeout=8.0, follow_redirects=False)
    own = client is None
    findings: list[Finding] = []
    seen: set[str] = set()
    lower_headers = dict(extra_headers or {})
    if cookie_header:
        lower_headers["Cookie"] = cookie_header

    try:
        for page in higher_doc.get("pages", []):
            url = page.get("url", "")
            if not url or url in seen:
                continue
            if not allow_external and not is_loopback_or_local(url):
                continue
            seen.add(url)

            try:
                lower_resp = http.get(url, headers=lower_headers)
            except httpx.HTTPError:
                continue
            if not _is_success(lower_resp.status_code):
                continue

            if check_anonymous:
                try:
                    anon_resp = http.get(url, headers={k: v for k, v in lower_headers.items() if k != "Cookie"})
                except httpx.HTTPError:
                    anon_resp = None
                if anon_resp is not None and _is_denied(
                    anon_resp.status_code, anon_resp.headers.get("location", "")
                ):
                    findings.append(
                        Finding(
                            id="authz-broken-access-control",
                            severity="high",
                            category="auth",
                            url=url,
                            description=(
                                f"URL discovered under the privileged session is also "
                                f"reachable (status {lower_resp.status_code}) with the "
                                f"lower-privilege session, while an anonymous request to "
                                f"the same URL was denied (status {anon_resp.status_code}) "
                                "-- this endpoint enforces *some* session but not the "
                                "*right* one. Verify whether the lower-privilege session "
                                "should be able to see this resource."
                            ),
                            evidence=f"lower={lower_resp.status_code} anon={anon_resp.status_code}",
                        )
                    )
                    continue
                if anon_resp is not None and _is_success(anon_resp.status_code):
                    # Anonymous access already succeeds -- this resource is
                    # confirmed public, so the lower-priv session reaching it
                    # too isn't a finding.
                    continue

            findings.append(
                Finding(
                    id="authz-still-accessible",
                    severity="medium",
                    category="auth",
                    url=url,
                    description=(
                        f"URL discovered under the privileged session was also reachable "
                        f"(status {lower_resp.status_code}) with the lower-privilege "
                        "session. Manually verify this is intentionally shared/public "
                        "access, not an access-control gap."
                    ),
                    evidence=f"lower={lower_resp.status_code}",
                )
            )
    finally:
        if own:
            http.close()

    return {"target": target, "findings": [f.model_dump() for f in findings]}
