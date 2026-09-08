"""Compound findings a triager will accept.

A missing header alone is usually excluded. XSS plus a readable session
cookie, or CORS reflection plus credentials plus SameSite=None, is a
report. Emitted in addition to the halves — never a substitute.
"""

from __future__ import annotations

from urllib.parse import urlparse

from shroodler.extractors.cookies import is_session_cookie
from shroodler.models import Finding, Page
from shroodler.urls import origin as origin_of

_XSS_IDS = frozenset({"payload-xss-reflect", "payload-xss-stored"})
_CORS_IDS = frozenset(
    {"cors-reflect-origin", "cors-wildcard-credentials", "cors-allow-any"}
)
_SYSTEMIC_CATEGORIES = frozenset({"header", "subresource"})


def _host(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def chain_findings(
    findings: list[Finding] | list[dict],
    pages: list[Page] | list[dict] | None = None,
) -> list[Finding]:
    """Return extra chain findings for the given set. Does not mutate input."""
    rows: list[dict] = []
    for item in findings:
        if isinstance(item, Finding):
            rows.append(item.model_dump(exclude_none=True))
        else:
            rows.append(dict(item))

    page_rows: list[dict] = []
    for page in pages or []:
        if isinstance(page, Page):
            page_rows.append(page.model_dump(exclude_none=True))
        else:
            page_rows.append(dict(page))

    by_host_ids: dict[str, set[str]] = {}
    by_host_url: dict[str, str] = {}
    for row in rows:
        host = _host(str(row.get("url") or ""))
        if not host:
            continue
        by_host_ids.setdefault(host, set()).add(str(row.get("id") or ""))
        by_host_url.setdefault(host, str(row.get("url") or ""))

    none_hosts: set[str] = set()
    httponly_hosts: dict[str, list[str]] = {}
    for page in page_rows:
        host = _host(str(page.get("url") or ""))
        for cookie in page.get("cookies") or []:
            name = cookie.get("name") if isinstance(cookie, dict) else cookie.name
            same = (
                cookie.get("same_site") if isinstance(cookie, dict) else cookie.same_site
            )
            http_only = (
                cookie.get("http_only") if isinstance(cookie, dict) else cookie.http_only
            )
            if not name:
                continue
            if same == "None" and is_session_cookie(str(name)):
                none_hosts.add(host)
            if http_only is False and is_session_cookie(str(name)):
                httponly_hosts.setdefault(host, []).append(str(name))

    out: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    def emit(fid: str, url: str, severity: str, description: str, evidence: str) -> None:
        key = (fid, origin_of(url) or url)
        if key in seen:
            return
        seen.add(key)
        out.append(
            Finding(
                id=fid,
                severity=severity,  # type: ignore[arg-type]
                category="auth",
                url=url,
                description=description,
                evidence=evidence,
            )
        )

    for host, ids in by_host_ids.items():
        url = by_host_url.get(host) or f"https://{host}/"
        xss = ids & _XSS_IDS
        if xss and (host in httponly_hosts or "cookie-not-httponly" in ids):
            names = ", ".join(sorted(set(httponly_hosts.get(host) or ["session"])))
            emit(
                "chain-xss-cookie-theft",
                url,
                "high",
                (
                    "Reflected/stored XSS on this host plus a session cookie without "
                    f"HttpOnly ({names}): script can read the session. Report the "
                    "pair, not the header alone."
                ),
                f"xss={sorted(xss)} cookies={names}",
            )
        cors = ids & _CORS_IDS
        if cors and (host in none_hosts or "cookie-samesite-none-without-secure" in ids):
            emit(
                "chain-cors-credentialed",
                url,
                "high",
                (
                    "CORS allows a foreign origin while a session cookie is "
                    "SameSite=None (or equivalent). A victim visit to the attacker "
                    "origin can make credentialed API calls. Confirm Allow-Credentials."
                ),
                f"cors={sorted(cors)}",
            )
    return out


def collapse_systemic_findings(findings: list[dict], *, min_count: int = 8) -> list[dict]:
    """Keep one row per header/subresource id when it repeats across many URLs."""
    counts: dict[str, int] = {}
    for row in findings:
        if row.get("category") in _SYSTEMIC_CATEGORIES:
            counts[str(row.get("id") or "")] = counts.get(str(row.get("id") or ""), 0) + 1

    collapse = {fid for fid, n in counts.items() if fid and n >= min_count}
    if not collapse:
        return findings

    seen: set[str] = set()
    out: list[dict] = []
    for row in findings:
        fid = str(row.get("id") or "")
        if fid not in collapse:
            out.append(row)
            continue
        if fid in seen:
            continue
        seen.add(fid)
        item = dict(row)
        n = counts[fid]
        extra = f"{n} pages"
        ev = item.get("evidence") or ""
        item["evidence"] = f"{ev}; clustered {extra}".lstrip("; ")
        desc = item.get("description") or fid
        if "clustered" not in desc:
            item["description"] = f"{desc} (same issue on {n} pages; clustered to one row)"
        out.append(item)
    return out
