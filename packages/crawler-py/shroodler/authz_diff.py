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


_AUTH_HEADER_NAMES = frozenset({"cookie", "authorization"})


def headers_from_auth_line(raw: str | None) -> dict[str, str]:
    """Turn a Cookie or Authorization line (or a bare cookie value) into headers."""
    text = (raw or "").strip()
    if not text:
        return {}
    if ":" in text:
        name, _, value = text.partition(":")
        name, value = name.strip(), value.strip()
        if not name:
            return {}
        lowered = name.lower()
        if lowered == "authorization":
            return {"Authorization": value}
        if lowered == "cookie":
            return {"Cookie": value}
        return {name: value}
    return {"Cookie": text}


def _strip_auth_headers(headers: dict[str, str]) -> dict[str, str]:
    return {k: v for k, v in headers.items() if k.lower() not in _AUTH_HEADER_NAMES}


_LOGIN_REDIRECT_HINTS = ("login", "signin", "sign-in", "log-in", "auth", "session/new")


# A marker shorter than this is too likely to appear in almost any
# response by coincidence (a first name, "admin", a single common word)
# to mean anything as "confirmation" -- silently upgrading every lead to
# confidence=confirmed off a degenerate marker would be worse than not
# confirming at all, since "confirmed" is exactly the tier meant to tell
# a human they can skip manual verification.
_MIN_MARKER_LENGTH = 8


def _confirm_ownership(
    body: str,
    *,
    higher_markers: list[str] | None,
    lower_markers: list[str] | None,
    anon_body: str | None,
) -> str | None:
    """Returns the specific higher-priv marker found in `body`, or None.
    A marker that ALSO appears in the lower-priv account's own identity
    markers is skipped -- that's ambiguous (could be either account's
    data), not confirmation it's specifically the higher-priv account's.
    Markers shorter than `_MIN_MARKER_LENGTH` are ignored (too likely to
    match by coincidence). A length floor alone is a weak proxy for
    "uniquely identifies an account" though -- plenty of 8+ character
    strings are page boilerplate (a footer's copyright line, a repeated
    CSS class, a nav-link URL fragment common to every page), so a
    marker is only ever treated as confirmation when the anonymous
    control response was actually captured (`anon_body is not None`)
    AND the marker is NOT also visible in it.

    `anon_body is None` (rather than falling back to a length-only
    check) covers every case where the anon probe didn't actually run or
    didn't come back: `check_anonymous=False`, the anon request raising
    a transport error, or the guardrail's enforcer denying that specific
    request. This matters for reproducibility: the same marker on the
    same target must not flip between "confirmed" and "not confirmed"
    across two runs purely because the anonymous request happened to
    succeed on one and time out on the other -- that would make the
    "confirmed" tier untrustworthy exactly where it needs to be trusted
    most. No anon body means no confirmation, full stop, not a silent
    downgrade to a weaker check.
    """
    if not higher_markers or anon_body is None:
        return None
    lower_set = set(lower_markers or [])
    for marker in higher_markers:
        if not marker or len(marker) < _MIN_MARKER_LENGTH:
            continue
        if marker not in body or marker in lower_set:
            continue
        if marker in anon_body:
            continue
        return marker
    return None


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
    enforcer=None,
    higher_priv_identity_markers: list[str] | None = None,
    lower_priv_identity_markers: list[str] | None = None,
    require_identity_confirmation: bool = False,
    gql_field_names: list[str] | None = None,
    higher_cookie_header: str | None = None,
) -> dict:
    """`enforcer`, if given, is a `shroodler_guardrails.policy.PolicyEnforcer`
    consulted before every live request this replay makes (both the
    lower-privilege and the anonymous control request) -- authz-diff fires
    real requests against a real target just like the payload tester does,
    so it is gated by the same scope/rate/blast-radius guardrail.

    This tool's own documented limitation is that it can't prove a
    reachable URL actually returns someone ELSE's data from a single
    replay -- it only proves the URL is reachable. `higher_priv_identity_markers`
    closes that gap when the caller (a human, or an agent that already
    knows both accounts' identities) supplies strings that uniquely
    identify the higher-privileged account's own data (an email,
    username, or record value only that account should see). If the
    lower-privileged session's response contains one of those markers,
    the lead is upgraded to `confidence: "confirmed"` -- this is no
    longer just "reachable", it's "returned the other account's data".
    `lower_priv_identity_markers` (the lower-priv account's OWN
    identifying strings) rules out the case where a marker match is
    coincidental because the response is just echoing the requester's
    own identity back (e.g. a generic "logged in as: X" banner) rather
    than the higher-priv account's data. Markers shorter than 8
    characters are ignored (see `_MIN_MARKER_LENGTH`) -- a short/common
    string ("admin", a first name) would coincidentally match almost any
    response and silently upgrade every lead to "confirmed", which
    defeats the whole point of the tier.

    With `require_identity_confirmation=True`, a lead that could NOT be
    confirmed this way is dropped entirely instead of reported at lower
    confidence -- "confirm or drop", per the caller's explicit choice,
    since an unconfirmed "reachable" signal may just as easily be a
    generic/public response as leaked cross-account data. Off by
    default: without markers, this parameter has no effect and every
    existing caller's behavior is unchanged.
    """
    target = higher_doc.get("target", "")
    if not allow_external and not is_loopback_or_local(target):
        raise ValueError(
            "authz-diff refuses non-local targets without --allow-external "
            "(only scan hosts you are authorized to test)"
        )
    http = client or httpx.Client(timeout=8.0, follow_redirects=False)
    own = client is None
    findings: list[dict] = []
    seen: set[str] = set()
    lower_headers = dict(extra_headers or {})
    lower_headers.update(headers_from_auth_line(cookie_header))
    higher_headers = dict(extra_headers or {})
    higher_headers.update(headers_from_auth_line(higher_cookie_header))

    try:
        for page in higher_doc.get("pages", []):
            url = page.get("url", "")
            if not url or url in seen:
                continue
            if not allow_external and not is_loopback_or_local(url):
                continue
            seen.add(url)

            if enforcer is not None:
                ok, _reason = enforcer.check(url)
                if not ok:
                    continue

            if higher_cookie_header:
                try:
                    http.get(url, headers=higher_headers)
                except httpx.HTTPError:
                    pass

            try:
                lower_resp = http.get(url, headers=lower_headers)
            except httpx.HTTPError:
                continue
            if not _is_success(lower_resp.status_code):
                continue

            anon_resp = None
            if check_anonymous and (enforcer is None or enforcer.check(url)[0]):
                try:
                    anon_headers = _strip_auth_headers(lower_headers)
                    anon_resp = http.get(url, headers=anon_headers)
                except httpx.HTTPError:
                    anon_resp = None
                if anon_resp is not None and _is_denied(
                    anon_resp.status_code, anon_resp.headers.get("location", "")
                ):
                    marker = _confirm_ownership(
                        lower_resp.text,
                        higher_markers=higher_priv_identity_markers,
                        lower_markers=lower_priv_identity_markers,
                        anon_body=anon_resp.text,
                    )
                    if require_identity_confirmation and marker is None:
                        continue
                    finding = Finding(
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
                    ).model_dump(exclude_none=True)
                    if marker is not None:
                        finding["confidence"] = "confirmed"
                        finding["description"] += (
                            f" CONFIRMED: response body contains the higher-privilege "
                            f"account's own identity marker ({marker!r})."
                        )
                    findings.append(finding)
                    continue
                if anon_resp is not None and _is_success(anon_resp.status_code):
                    # Anonymous access already succeeds -- this resource is
                    # confirmed public, so the lower-priv session reaching it
                    # too isn't a finding.
                    continue

            marker = _confirm_ownership(
                lower_resp.text,
                higher_markers=higher_priv_identity_markers,
                lower_markers=lower_priv_identity_markers,
                anon_body=anon_resp.text if anon_resp is not None else None,
            )
            if require_identity_confirmation and marker is None:
                continue
            finding = Finding(
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
            ).model_dump(exclude_none=True)
            if marker is not None:
                finding["confidence"] = "confirmed"
                finding["description"] += (
                    f" CONFIRMED: response body contains the higher-privilege "
                    f"account's own identity marker ({marker!r})."
                )
            findings.append(finding)

        gql_urls = _graphql_urls(higher_doc)
        field_names = _graphql_field_names(higher_doc, gql_field_names)
        for url in gql_urls:
            if not allow_external and not is_loopback_or_local(url):
                continue
            if enforcer is not None and not enforcer.check(url)[0]:
                continue
            from shroodler.extractors.graphql import replay_graphql_fields

            extra = replay_graphql_fields(
                url,
                http,
                lower_headers=lower_headers,
                field_names=field_names or None,
                enforcer=enforcer,
            )
            findings.extend(f.model_dump(exclude_none=True) for f in extra)
    finally:
        if own:
            http.close()

    return {"target": target, "findings": findings}


def _graphql_urls(doc: dict) -> list[str]:
    out: list[str] = []
    for page in doc.get("pages") or []:
        url = str(page.get("url") or "")
        if url and "graphql" in url.lower() and url not in out:
            out.append(url)
    for ep in doc.get("js_endpoints") or []:
        source = str(ep.get("source") or "")
        marker = str(ep.get("endpoint") or "")
        if "graphql" in (source + marker).lower() and source.startswith("http") and source not in out:
            out.append(source)
    return out


def _graphql_field_names(doc: dict, extra: list[str] | None) -> list[str]:
    from shroodler.extractors.graphql import field_name_from_endpoint

    names: list[str] = []
    seen: set[str] = set()
    for name in extra or []:
        if name and name not in seen:
            seen.add(name)
            names.append(name)
    for ep in doc.get("js_endpoints") or []:
        extracted = field_name_from_endpoint(str(ep.get("endpoint") or ""))
        if extracted and extracted not in seen:
            seen.add(extracted)
            names.append(extracted)
    return names
