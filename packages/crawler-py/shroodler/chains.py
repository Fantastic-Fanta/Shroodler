"""Compound findings a triager will accept.

A missing header alone is usually excluded. XSS plus a readable session
cookie, or CORS reflection plus credentials plus SameSite=None, is a
report. Emitted in addition to the halves — never a substitute.
"""

from __future__ import annotations

from shroodler.extractors.cookies import is_session_cookie
from shroodler.models import Finding, Page
from shroodler.urls import origin as origin_of

_XSS_IDS = frozenset({"payload-xss-reflect", "payload-xss-stored"})
_SYSTEMIC_CATEGORIES = frozenset({"header", "subresource"})
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _origin_key(url: str) -> str:
    return origin_of(url) or url


def _acac_true(evidence: str | None) -> bool:
    return "acac=true" in (evidence or "").lower().replace(" ", "")


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

    by_origin_ids: dict[str, set[str]] = {}
    by_origin_url: dict[str, str] = {}
    cors_acac: set[str] = set()
    for row in rows:
        url = str(row.get("url") or "")
        origin = _origin_key(url)
        if not origin:
            continue
        fid = str(row.get("id") or "")
        by_origin_ids.setdefault(origin, set()).add(fid)
        by_origin_url.setdefault(origin, url)
        if fid == "cors-reflect-origin" and _acac_true(row.get("evidence")):
            cors_acac.add(origin)

    none_origins: set[str] = set()
    readable_session: dict[str, list[str]] = {}
    for page in page_rows:
        origin = _origin_key(str(page.get("url") or ""))
        for cookie in page.get("cookies") or []:
            name = cookie.get("name") if isinstance(cookie, dict) else cookie.name
            same = (
                cookie.get("same_site") if isinstance(cookie, dict) else cookie.same_site
            )
            http_only = (
                cookie.get("http_only") if isinstance(cookie, dict) else cookie.http_only
            )
            if not name or not is_session_cookie(str(name)):
                continue
            if same == "None":
                none_origins.add(origin)
            if http_only is False:
                readable_session.setdefault(origin, []).append(str(name))

    out: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    def emit(fid: str, url: str, severity: str, description: str, evidence: str) -> None:
        key = (fid, _origin_key(url))
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

    for origin, ids in by_origin_ids.items():
        url = by_origin_url.get(origin) or origin
        xss = ids & _XSS_IDS
        names = sorted(set(readable_session.get(origin) or []))
        if xss and names:
            emit(
                "chain-xss-cookie-theft",
                url,
                "high",
                (
                    "Reflected/stored XSS on this origin plus a session cookie without "
                    f"HttpOnly ({', '.join(names)}): script can read the session. "
                    "Report the pair, not the header alone."
                ),
                f"xss={sorted(xss)} cookies={', '.join(names)}",
            )
        if origin in cors_acac and origin in none_origins:
            emit(
                "chain-cors-credentialed",
                url,
                "high",
                (
                    "CORS reflects a foreign origin with Access-Control-Allow-Credentials "
                    "while a session cookie is SameSite=None. A victim visit to the "
                    "attacker origin can make credentialed API calls."
                ),
                "cors=cors-reflect-origin ACAC=true SameSite=None",
            )
    return out


def collapse_systemic_findings(findings: list[dict], *, min_count: int = 8) -> list[dict]:
    """Keep one row per origin+header/subresource id when it repeats across many URLs."""
    counts: dict[tuple[str, str], int] = {}
    for row in findings:
        if row.get("category") not in _SYSTEMIC_CATEGORIES:
            continue
        fid = str(row.get("id") or "")
        if not fid:
            continue
        key = (_origin_key(str(row.get("url") or "")), fid)
        counts[key] = counts.get(key, 0) + 1

    collapse = {key for key, n in counts.items() if n >= min_count}
    if not collapse:
        return findings

    best: dict[tuple[str, str], dict] = {}
    for row in findings:
        fid = str(row.get("id") or "")
        key = (_origin_key(str(row.get("url") or "")), fid)
        if key not in collapse:
            continue
        prev = best.get(key)
        if prev is None or _SEV_RANK.get(str(row.get("severity") or "info"), 9) < _SEV_RANK.get(
            str(prev.get("severity") or "info"), 9
        ):
            best[key] = row

    seen: set[tuple[str, str]] = set()
    out: list[dict] = []
    for row in findings:
        fid = str(row.get("id") or "")
        key = (_origin_key(str(row.get("url") or "")), fid)
        if key not in collapse:
            out.append(row)
            continue
        if key in seen:
            continue
        seen.add(key)
        item = dict(best[key])
        n = counts[key]
        extra = f"{n} pages"
        ev = item.get("evidence") or ""
        item["evidence"] = f"{ev}; clustered {extra}".lstrip("; ")
        desc = item.get("description") or fid
        if "clustered" not in desc:
            item["description"] = f"{desc} (same issue on {n} pages; clustered to one row)"
        out.append(item)
    return out
