"""A risk score summarizing a scan's findings, for an executive-summary
view.

Deliberately scored off DISTINCT finding ids per severity, not raw
per-finding-instance counts: a single missing-CSP header repeated across
500 crawled pages is one real issue, not 500 -- scoring on raw instance
count would make that one systemic misconfiguration dwarf a scan that
found five genuinely distinct critical vulnerabilities on one page,
which is exactly backwards for an executive reading one number. This
uses the same per-id grouping `group_findings()` already computes for
the technical summary table, so the two views can never disagree about
"how many distinct issues" exist.

Not consumed anywhere machine-readable (not in the JSON `render()` path,
not read by `diff --gate`) -- purely a rendered-report artifact, so
there's no CI-gating behavior riding on the exact numbers here.
"""

from __future__ import annotations

# Contribution to the score per distinct finding id at a given severity.
# The cap at 100 (see compute_risk_score) means this is NOT simply "the
# top of the scale is reserved for real critical/high volume" -- a large
# enough pile of mediums/lows reaches the same cap. What the cap actually
# buys is just: doubling an already-bad scan's low-severity noise doesn't
# make the number climb forever. The severity FLOOR below is what
# actually keeps a single critical from being outscored by a pile of
# lows/mediums.
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

_GRADE_ORDER = ["A", "B", "C", "D", "F"]

# A severity floor on the GRADE (not the numeric score): review found
# that a single critical (weight 20) landed in the same "B" band as a
# pile of unrelated mediums/lows -- e.g. jwt-weak-secret (full auth
# bypass, forge any token) rendering the same blue "B" badge as 12
# missing-CSP-style header notes. Every mature scoring rubric floors the
# grade by worst-severity-present for exactly this reason: the letter
# grade must never let volume of minor issues outrank the presence of
# one severe one.
_GRADE_FLOOR_BY_SEVERITY = {
    "critical": "F",
    "high": "D",
    "medium": "C",
}


def _grade_for(score: int) -> str:
    for ceiling, grade in _GRADE_BANDS:
        if score <= ceiling:
            return grade
    return "F"


def _worse_grade(a: str, b: str) -> str:
    return a if _GRADE_ORDER.index(a) > _GRADE_ORDER.index(b) else b


def compute_risk_score(grouped_findings: list[dict]) -> dict:
    """`grouped_findings` is the output of reportgen.group_findings() --
    one row per distinct finding id, each carrying its `severity`."""
    severity_counts: dict[str, int] = {sev: 0 for sev in _SEVERITY_WEIGHT}
    for g in grouped_findings:
        # Bucket anything outside the five known severities into
        # "medium" -- the conservative choice -- rather than letting
        # severity_counts silently grow an extra key the template never
        # reads: that would have made a report showing "4 findings" print
        # "0 critical, 0 high, 0 medium, 0 low, 0 info" right below it if
        # a finding's severity string were ever off-vocabulary (a typo,
        # a hand-edited findings file, a future new severity level).
        sev = g.get("severity")
        if sev not in _SEVERITY_WEIGHT:
            sev = "medium"
        severity_counts[sev] += 1
    weighted = sum(_SEVERITY_WEIGHT.get(sev, 0) * count for sev, count in severity_counts.items())
    score = min(100, weighted)
    grade = _grade_for(score)
    for sev, floor in _GRADE_FLOOR_BY_SEVERITY.items():
        if severity_counts.get(sev):
            grade = _worse_grade(grade, floor)
            break
    return {
        "score": score,
        "grade": grade,
        "severity_counts": severity_counts,
        "partial_coverage": _has_coverage_gap(grouped_findings),
    }


def _has_coverage_gap(grouped_findings: list[dict]) -> bool:
    """True when the scan itself reported that some part of it didn't
    run (a WAF blocked it, a probe was skipped, a redirect chain was
    truncated) -- a clean grade on a scan that couldn't fully test the
    target is the most expensive kind of misread this report can cause,
    so the executive summary caveats it explicitly rather than only
    ever showing a bare letter grade.

    Matched on the finding id's own text (not category: reportgen's
    group_findings() output -- what this function actually receives --
    doesn't carry the original category field, only id/severity/
    description/urls/count) against every known skip/truncation/
    challenge id in both crawler engines: cors-probe-skipped,
    graphql-probe-skipped, session-checks-skipped-headless,
    redirect-chain-truncated, waf-challenge, waf-blocking-active-scan."""
    for g in grouped_findings:
        fid = str(g.get("id", "")).lower()
        if "skipped" in fid or "truncated" in fid or "challenge" in fid or "blocking" in fid:
            return True
    return False
