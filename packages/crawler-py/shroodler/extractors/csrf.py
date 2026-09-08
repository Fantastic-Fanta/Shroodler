"""Authenticated CSRF: cookie session + state-changing form, no token.

Only fires when a session cookie is SameSite=None (cross-site POSTs still
send it) and a POST/PUT/PATCH/DELETE form on that origin has no CSRF
field. Lax/default cookies are not flagged — modern browsers already
withhold those on cross-site POSTs.

An optional Origin probe (gated like CORS) confirms the write endpoint
reflects a foreign Origin on OPTIONS. That is supporting CORS evidence,
not a substitute for a manual POST. Probes are anonymous OPTIONS only.
"""

from __future__ import annotations

from urllib.parse import unquote, urlparse

from shroodler.csrf import csrf_harvest_url_ok, is_csrf_field_name
from shroodler.extractors.cookies import is_session_cookie
from shroodler.extractors.cors import ATTACKER_ORIGIN, header_get
from shroodler.models import Finding, Page
from shroodler.urls import is_loopback_or_local, normalize_url, origin as origin_of, same_origin

_WRITE = {"POST", "PUT", "PATCH", "DELETE"}
MAX_ORIGIN_PROBES = 16


def _write_action(page_url: str, action: str) -> str | None:
    raw = (action or "").strip()
    if not raw or raw.startswith("#"):
        raw = page_url
    resolved = normalize_url(page_url, raw)
    if not resolved:
        return None
    if not same_origin(resolved, page_url):
        return None
    if not csrf_harvest_url_ok(resolved, allow_external=True):
        return None
    return resolved


def _norm_path(path: str) -> str:
    p = unquote(path or "/")
    while "//" in p:
        p = p.replace("//", "/")
    if not p.startswith("/"):
        p = "/" + p
    return p.lower()


def _acam_allows(acam: str, method: str) -> bool:
    if not acam:
        return True
    tokens = {t.strip().lower() for t in acam.split(",") if t.strip()}
    if "*" in tokens:
        return True
    return method.lower() in tokens


def _method_from_evidence(evidence: str | None) -> str:
    for part in (evidence or "").split():
        if part.lower().startswith("method="):
            return part.split("=", 1)[1].upper()
    return "POST"


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
                if method not in _WRITE:
                    continue
                if any(is_csrf_field_name(f.name) for f in form.fields):
                    continue
                action = _write_action(page.url, form.action or page.url)
                if not action:
                    continue
                key = (action, method)
                if key in seen:
                    continue
                seen.add(key)
                out.append(
                    Finding(
                        id="csrf-state-change-unprotected",
                        severity="medium",
                        category="auth",
                        url=action,
                        description=(
                            f"{method} {action} is a state-changing form with no CSRF "
                            f"token, and session cookie(s) {cookie_note} use "
                            "SameSite=None so a third-party origin can include them "
                            "on a cross-site POST. Confirm the endpoint also lacks "
                            "an Origin/Referer allowlist before reporting."
                        ),
                        evidence=f"cookies={cookie_note} method={method} action={action}",
                    )
                )
    return out


def confirm_csrf_origin(
    findings: list[Finding],
    pages: list[Page],
    http,
    *,
    allow_external: bool = False,
    exclude_paths: list[str] | None = None,
) -> list[Finding]:
    """Anonymous OPTIONS of the write action with Origin: attacker. No GET."""
    del pages  # findings already carry the resolved write URL
    excluded = [_norm_path(p if p.startswith("/") else "/" + p) for p in (exclude_paths or [])]
    probed: set[str] = set()
    n = 0
    out: list[Finding] = []
    for finding in findings:
        if finding.id != "csrf-state-change-unprotected":
            out.append(finding)
            continue
        action = finding.url
        origin = origin_of(action)
        if not csrf_harvest_url_ok(action, allow_external=allow_external):
            out.append(finding)
            continue
        if not is_loopback_or_local(origin) and not allow_external:
            out.append(finding)
            continue
        path = _norm_path(urlparse(action).path or "/")
        if excluded and any(path.startswith(ep) for ep in excluded):
            out.append(finding)
            continue
        if n >= MAX_ORIGIN_PROBES or action in probed:
            out.append(finding)
            continue
        probed.add(action)
        n += 1
        method = _method_from_evidence(finding.evidence)
        headers = {
            "Origin": ATTACKER_ORIGIN,
            "Access-Control-Request-Method": method,
        }
        try:
            opt = http.request("OPTIONS", action, headers, anonymous=True)
        except TypeError:
            out.append(finding)
            continue
        if getattr(opt, "error", None) or getattr(opt, "status_code", 0) == 0:
            out.append(finding)
            continue
        acao = header_get(getattr(opt, "headers", None) or {}, "access-control-allow-origin")
        acam = header_get(getattr(opt, "headers", None) or {}, "access-control-allow-methods")
        if acao == ATTACKER_ORIGIN and _acam_allows(acam, method):
            out.append(
                finding.model_copy(
                    update={
                        "evidence": (
                            (finding.evidence or "")
                            + f"; Origin {ATTACKER_ORIGIN} reflected on OPTIONS {action}"
                        ),
                        "description": (
                            finding.description
                            + " OPTIONS reflects a foreign Origin (CORS); this is "
                            "supporting evidence, not proof that a cross-site POST "
                            "would succeed. Confirm Origin/Referer on the write verb."
                        ),
                    }
                )
            )
            continue
        out.append(finding)
    return out
