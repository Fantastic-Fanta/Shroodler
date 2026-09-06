"""WAF-coverage regression as a first-class finding.

Nobody treats "my own protection silently got weaker" as a tracked
finding today; every piece this needs already exists (WAF/bot-mitigation
challenge detection -- category "waf-challenge" -- and the `history`/
`trend` scan-comparison mechanism), it's just never been correlated.
This does: compute what fraction of a scan's pages showed WAF-challenge
evidence, and compare that fraction between two scans of the same
target. A meaningful drop becomes a real finding (`waf-coverage-drop`,
category "waf-challenge") an operator can catch via `trend`/CI the same
way they'd catch a new vulnerability, not something only noticed after
an incident.

"Coverage" here means "fraction of crawled pages where an active probe
tripped a visible WAF/bot-mitigation response", not "fraction of the
site actually protected" -- a page never challenged might be legitimately
excluded from WAF rules, or the WAF might protect it in ways this
crawl's specific requests never trigger. Treat a coverage drop as
"investigate whether protection changed", not proof it did.
"""

from __future__ import annotations


def waf_coverage(doc: dict) -> float:
    """Fraction (0.0-1.0) of this scan's pages that have at least one
    waf-challenge-category finding. 0.0 (not None) when there are no
    pages at all, so callers can compare two empty scans without a
    special case."""
    pages = doc.get("pages", [])
    if not pages:
        return 0.0
    challenged_urls = {
        f.get("url", "") for f in doc.get("findings", []) if f.get("category") == "waf-challenge"
    }
    challenged_pages = sum(1 for p in pages if p.get("url", "") in challenged_urls)
    return challenged_pages / len(pages)


def waf_coverage_regression(
    older: dict,
    newer: dict,
    *,
    drop_threshold: float = 0.2,
) -> dict | None:
    """Returns a finding dict if WAF coverage dropped by more than
    `drop_threshold` (as an absolute fraction, e.g. 0.2 = 20 percentage
    points) between `older` and `newer`, else None.

    A coverage fraction is only meaningful if the two scans crawled a
    comparable number of pages: an older scan blocked to 5 pages with
    4/5 (80%) challenged, and a newer scan reaching 50 pages (WAF
    reconfigured, or the crawler improved) with 25/50 (50%) challenged,
    is a "30-point drop" by the raw fraction alone even though the WAF
    triggered on 5x more pages in absolute terms -- arguably an
    improvement, not a regression. Page counts are always included in
    the finding's evidence/description so this isn't hidden from a
    reader, and the finding is downgraded to at most "medium" severity
    (never suppressed outright -- a real regression can still coincide
    with a page-count change) when the two scans' page counts differ by
    more than 2x in either direction.
    """
    old_pages = len(older.get("pages", []))
    new_pages = len(newer.get("pages", []))
    old_coverage = waf_coverage(older)
    new_coverage = waf_coverage(newer)
    drop = old_coverage - new_coverage
    if drop <= drop_threshold:
        return None

    smaller, larger = sorted((old_pages, new_pages))
    page_count_mismatch = larger > 0 and (smaller == 0 or larger / smaller > 2)

    severity = "critical" if drop >= 0.5 else "high" if drop >= 0.3 else "medium"
    caveat = ""
    if page_count_mismatch:
        severity = "medium"
        caveat = (
            f" NOTE: the two scans crawled very different numbers of pages "
            f"({old_pages} vs {new_pages}) -- this coverage comparison may not be "
            "meaningful; verify before treating it as a real regression."
        )

    return {
        "id": "waf-coverage-drop",
        "severity": severity,
        "category": "waf-challenge",
        "url": newer.get("target", ""),
        "description": (
            f"WAF/bot-mitigation coverage dropped from {old_coverage:.0%} "
            f"({old_pages} pages) to {new_coverage:.0%} ({new_pages} pages) between "
            "scans -- investigate whether protection was weakened, removed, or "
            f"reconfigured, rather than treating a quieter scan as good news.{caveat}"
        ),
        "evidence": (
            f"older={old_coverage:.4f} ({old_pages} pages) "
            f"newer={new_coverage:.4f} ({new_pages} pages) drop={drop:.4f}"
        ),
        "page_count_mismatch": page_count_mismatch,
    }
