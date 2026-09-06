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
    """
    old_coverage = waf_coverage(older)
    new_coverage = waf_coverage(newer)
    drop = old_coverage - new_coverage
    if drop <= drop_threshold:
        return None
    severity = "critical" if drop >= 0.5 else "high" if drop >= 0.3 else "medium"
    return {
        "id": "waf-coverage-drop",
        "severity": severity,
        "category": "waf-challenge",
        "url": newer.get("target", ""),
        "description": (
            f"WAF/bot-mitigation coverage dropped from {old_coverage:.0%} to "
            f"{new_coverage:.0%} of crawled pages between scans -- investigate "
            "whether protection was weakened, removed, or reconfigured, rather than "
            "treating a quieter scan as good news."
        ),
        "evidence": f"older={old_coverage:.4f} newer={new_coverage:.4f} drop={drop:.4f}",
    }
