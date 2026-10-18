"""Engine-independent helpers that survive the Python crawler's retirement.

The Python in-process crawler (``crawler.py``) was retired once the Go engine
(``shroodler-go`` via ``go_engine.py``) became the sole crawl path. A few of its
helpers are not crawl-loop machinery at all -- they turn a single already-fetched
response into a ``Page``/findings (``page_from_fetch``) or collapse/dedup
findings and endpoints -- and are still called by the captured-session replay
path (``sessions.py``) and the Slither ingest (``slither_ingest.py``). They live
here now so those consumers keep working without the crawl loop.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from shroodler.extractors.challenge import detect_challenge
from shroodler.extractors.client_side import extract_client_side
from shroodler.extractors.cloud_storage import extract_cloud_buckets
from shroodler.extractors.cookies import extract_cookies
from shroodler.extractors.forms import extract_forms
from shroodler.extractors.headers import extract_headers
from shroodler.extractors.html_markup import extract_html_markup
from shroodler.extractors.js_api_surface import extract_js_api_surface
from shroodler.extractors.js_endpoints import extract_js_endpoints
from shroodler.extractors.jwt_audit import audit_text as audit_jwts
from shroodler.extractors.oauth import check_oauth_authorize_url
from shroodler.extractors.secrets import scan_text
from shroodler.extractors.subresource import extract_subresource_findings
from shroodler.extractors.verbose import extract_verbose_errors
from shroodler.models import Finding, HeaderAnalysis, JsEndpoint, Page
from shroodler.modes.static import FetchResult
from shroodler.urls import origin as origin_of
from shroodler.urls import query_param_names


def _content_type(headers: dict[str, str]) -> str:
    for k, v in headers.items():
        if k.lower() == "content-type":
            return v.lower()
    return ""


def page_from_fetch(
    result: FetchResult,
    *,
    cookies_attrs_reliable: bool = True,
    extra_secret_rules: list[dict] | None = None,
    plugin_checks: list | None = None,
) -> tuple[Page, list[Finding], list[JsEndpoint]]:
    cookies, cookie_findings = extract_cookies(
        result.set_cookies, result.url, attrs_reliable=cookies_attrs_reliable
    )
    # A failed fetch (connection error, TLS failure, timeout -- see
    # FetchResult.error) carries an empty headers dict, not evidence the
    # target actually omitted every security header. Treating that as
    # "missing-csp", "missing-hsts", etc. is a false finding manufactured
    # from the absence of a response, not from the response itself.
    if result.status_code == 0:
        headers, header_findings = HeaderAnalysis(present=[], missing=[]), []
    else:
        headers, header_findings = extract_headers(result.headers, result.url)

    challenge = detect_challenge(
        result.headers, result.text, result.status_code, result.set_cookies
    )
    if challenge:
        # This page is a WAF/bot-mitigation interstitial, not real target
        # content. Keep header/cookie extraction (those describe the actual
        # HTTP exchange) but skip everything that would otherwise parse the
        # challenge HTML as if it were the site -- forms, secrets, JS
        # endpoints, verbose errors, markup checks would all be noise or
        # false positives here.
        page = Page(
            url=result.url,
            status_code=result.status_code,
            params=query_param_names(result.url),
            cookies=cookies,
            headers=headers,
        )
        challenge = challenge.model_copy(update={"url": result.url})
        return page, [challenge, *cookie_findings, *header_findings], []

    js_files: list[str] = []
    forms = []
    form_findings: list[Finding] = []
    endpoints: list[JsEndpoint] = []
    ep_findings: list[Finding] = []
    if result.text:
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(result.text, "lxml")
        for script in soup.find_all("script", src=True):
            src = script.get("src")
            if src:
                js_files.append(src)
        ctype = _content_type(result.headers)
        is_html = "html" in ctype or result.text.lstrip().startswith("<")
        is_js = "javascript" in ctype or result.url.endswith(".js")
        if is_html:
            forms, form_findings = extract_forms(result.text, result.url)
        if is_js or is_html:
            endpoints, ep_findings = extract_js_endpoints(result.url, result.text)
            api_eps, api_findings = extract_js_api_surface(result.url, result.text)
            endpoints.extend(api_eps)
            ep_findings.extend(api_findings)
    verbose_findings = extract_verbose_errors(result.text, result.url, result.status_code)
    secret_findings = scan_text(result.text, result.url, extra_rules=extra_secret_rules)
    bucket_findings = extract_cloud_buckets(result.text, result.url)
    client_side_findings = extract_client_side(result.text, result.url)
    jwt_findings = audit_jwts(result.text, result.url)
    markup_findings = extract_html_markup(result.text, result.url)
    oauth_findings = check_oauth_authorize_url(result.url)
    subresource_findings = extract_subresource_findings(result.text, result.url)
    page = Page(
        url=result.url,
        status_code=result.status_code,
        forms=forms,
        params=query_param_names(result.url),
        cookies=cookies,
        headers=headers,
        js_files=js_files,
    )
    all_f = (
        form_findings
        + cookie_findings
        + header_findings
        + verbose_findings
        + secret_findings
        + bucket_findings
        + client_side_findings
        + jwt_findings
        + markup_findings
        + oauth_findings
        + subresource_findings
        + ep_findings
    )
    if plugin_checks and result.text:
        from shroodler.plugins import run_checks

        all_f = all_f + run_checks(
            plugin_checks,
            url=result.url,
            body=result.text,
            headers=result.headers,
            status_code=result.status_code,
        )
    return page, all_f, endpoints


def _with_capture_source(finding: Finding) -> Finding:
    ev = finding.evidence or ""
    if "source=capture" in ev.lower().replace(" ", ""):
        return finding
    stamped = f"{ev}; source=capture" if ev else "source=capture"
    return finding.model_copy(update={"evidence": stamped})


def _collapsed_evidence(group: list[Finding], sample: str) -> str:
    n = len(group)
    ev = f"Affects {n} pages; sample: {sample}"
    if any("source=capture" in (f.evidence or "").lower().replace(" ", "") for f in group):
        ev += "; source=capture"
    return ev


_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


_HEADER_HOST_IDS = frozenset(
    {
        "missing-csp",
        "missing-hsts",
        "missing-x-frame-options",
        "missing-x-content-type-options",
        "missing-referrer-policy",
    }
)
_AFFECTS_PAGES = re.compile(r"Affects\s+(\d+)\s+pages", re.I)


def _finding_host(url: str) -> str:
    parsed = urlparse(url or "")
    return (parsed.netloc or parsed.hostname or url or "").lower()


def _pages_in_evidence(finding: Finding) -> int:
    evidence = finding.evidence or ""
    match = _AFFECTS_PAGES.search(evidence)
    if match:
        try:
            return int(match.group(1))
        except (TypeError, ValueError):
            return 1
    return 1


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    # Header-category findings that are sitewide (same rule fires on many pages)
    # get collapsed to one finding per origin with a count in evidence. This
    # prevents 50+ identical rows in reports for issues like missing CSP or
    # absent Referrer-Policy that apply to an entire domain, not a single page.
    # Categories whose findings are sitewide by nature (same rule fires
    # on many pages due to a server/policy issue, not a per-URL bug).
    # Cookie security flags (insecure-cookie, cookie-not-httponly) are domain-
    # level policy decisions: every page that touches the cookie has the same
    # flag missing. Collapse them sitewide the same way header findings are.
    _SITEWIDE_CATEGORIES = frozenset({"header", "subresource", "cookie"})

    header_by_key: dict[tuple[str, str, str], list[Finding]] = {}
    rest: list[Finding] = []
    for f in findings:
        if f.category in _SITEWIDE_CATEGORIES:
            # Cookie findings: include evidence (cookie name) in the key so
            # distinct cookies are separate rows even with the same finding id.
            ev = f.evidence if f.category == "cookie" else ""
            host = _finding_host(f.url) if f.id in _HEADER_HOST_IDS else origin_of(f.url)
            key = (f.id, host, ev)
            header_by_key.setdefault(key, []).append(f)
        else:
            rest.append(f)

    collapsed: list[Finding] = []
    for (fid, orig, _ev), group in header_by_key.items():
        first = min(group, key=lambda f: _SEV_RANK.get(f.severity, 9))
        richest = max(group, key=_pages_in_evidence)
        n = max(len(group), _pages_in_evidence(richest))
        if n == 1:
            collapsed.append(first)
        elif _pages_in_evidence(richest) >= len(group) and _pages_in_evidence(richest) > 1:
            collapsed.append(richest)
        else:
            sample = first.url
            collapsed.append(
                Finding(
                    id=fid,
                    severity=first.severity,
                    category=first.category,
                    url=origin_of(first.url) if orig and "://" not in orig else orig or first.url,
                    description=first.description,
                    evidence=_collapsed_evidence(group, sample),
                    confidence=first.confidence,
                )
            )

    # Deduplicate non-header findings by (id, url) as before
    out: list[Finding] = list(collapsed)
    seen: set[tuple[str, str]] = set()
    for f in rest:
        key = (f.id, f.url)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def _dedupe_endpoints(items: list[JsEndpoint]) -> list[JsEndpoint]:
    out: list[JsEndpoint] = []
    seen: set[tuple[str, str]] = set()
    for item in items:
        key = (item.source, item.endpoint)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out
