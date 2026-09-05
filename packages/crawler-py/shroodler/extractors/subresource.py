"""Mixed-content and Subresource Integrity (SRI) checks.

Python-only and opt-in (--check-subresources): unlike the always-on
extractors in this package, these require parsing the HTML body for
<script>/<link> tags with their src/href, and the Go crawler does not
implement them. Gating behind an explicit off-by-default flag (rather than
running unconditionally like html_markup/cookies/headers) keeps a default
`crawl` producing identical findings on both engines, which is what
packages/parity-tests/run_parity.py enforces. See docs/features.md for the
Python-only-features note.
"""

from __future__ import annotations

from urllib.parse import urlparse

from bs4 import BeautifulSoup

from shroodler.models import Finding
from shroodler.urls import same_origin

# Tags/attributes that fetch a subresource and are worth an SRI check.
# Both are load-bearing enough (execute or apply on the page) that a
# tampered cross-origin copy is a real compromise, unlike e.g. <img>.
_SRI_TAGS = (("script", "src"), ("link", "href"))


def _is_stylesheet_link(tag) -> bool:
    rel = tag.get("rel")
    if rel is None:
        return False
    rels = {r.lower() for r in rel} if isinstance(rel, list) else {str(rel).lower()}
    return "stylesheet" in rels


def _finding(fid: str, severity: str, page_url: str, evidence: str, description: str) -> Finding:
    return Finding(
        id=fid,
        severity=severity,
        category="subresource",
        url=page_url,
        description=description,
        evidence=evidence,
    )


def extract_subresource_findings(body: str, page_url: str) -> list[Finding]:
    if not body:
        return []
    page_scheme = urlparse(page_url).scheme.lower()
    soup = BeautifulSoup(body, "lxml")
    findings: list[Finding] = []

    for tag_name, attr in _SRI_TAGS:
        for tag in soup.find_all(tag_name):
            if tag_name == "link" and not _is_stylesheet_link(tag):
                continue
            src = tag.get(attr)
            if not src:
                continue
            src = src.strip()
            if not src or src.startswith(("data:", "javascript:", "#")):
                continue
            src_scheme = urlparse(src).scheme.lower()
            is_cross_origin = src_scheme in ("http", "https") and not same_origin(src, page_url)
            if is_cross_origin and not tag.get("integrity"):
                findings.append(
                    _finding(
                        "sri-missing",
                        "low",
                        page_url,
                        src,
                        f"Cross-origin <{tag_name}> loaded without a Subresource "
                        f"Integrity (integrity=) attribute: {src}",
                    )
                )
            if page_scheme == "https" and src_scheme == "http":
                findings.append(
                    _finding(
                        "mixed-content",
                        "medium",
                        page_url,
                        src,
                        f"HTTPS page loads an insecure http:// <{tag_name}> subresource: {src}",
                    )
                )

    return findings
