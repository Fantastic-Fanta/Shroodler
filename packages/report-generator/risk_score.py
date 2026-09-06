"""A single 0-100 risk score summarizing a scan's findings, for an
executive-summary view.

Deliberately scored off DISTINCT finding ids per severity, not raw
per-finding-instance counts: a single missing-CSP header repeated across
500 crawled pages is one real issue, not 500 -- scoring on raw instance
count would make that one systemic misconfiguration dwarf a scan that
found five genuinely distinct critical vulnerabilities on one page,
which is exactly backwards for an executive reading one number. This
uses the same per-id grouping `group_findings()` already computes for
the technical summary table, so the two views can never disagree about
"how many distinct issues" exist.
"""

from __future__ import annotations

# Contribution to the score per distinct finding id at a given severity.
# Deliberately not linear-additive without a cap: min(100, ...) below
# means an executive score never implies a scan "twice as bad" just
# because it happened to have twice as many low-severity notes -- the
# top of the scale is reserved for scans with real critical/high volume.
_SEVERITY_WEIGHT = {
    "critical": 20,
    "high": 10,
    "medium": 4,
    "low": 1,
    "info": 0,
}

_GRADE_BANDS = (
    (0, "A"),
    (20, "B"),
    (40, "C"),
    (60, "D"),
    (100, "F"),
)


def _grade_for(score: int) -> str:
    for ceiling, grade in _GRADE_BANDS:
        if score <= ceiling:
            return grade
    return "F"


def compute_risk_score(grouped_findings: list[dict]) -> dict:
    """`grouped_findings` is the output of reportgen.group_findings() --
    one row per distinct finding id, each carrying its `severity`."""
    severity_counts: dict[str, int] = {sev: 0 for sev in _SEVERITY_WEIGHT}
    for g in grouped_findings:
        sev = g.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    weighted = sum(_SEVERITY_WEIGHT.get(sev, 0) * count for sev, count in severity_counts.items())
    score = min(100, weighted)
    return {
        "score": score,
        "grade": _grade_for(score),
        "severity_counts": severity_counts,
    }
