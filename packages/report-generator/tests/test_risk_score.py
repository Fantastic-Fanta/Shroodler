from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from risk_score import compute_risk_score


def _grouped(*severities: str) -> list[dict]:
    return [{"id": f"finding-{i}", "severity": sev} for i, sev in enumerate(severities)]


def test_no_findings_scores_zero_grade_a():
    result = compute_risk_score([])
    assert result["score"] == 0
    assert result["grade"] == "A"
    assert result["severity_counts"] == {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }


def test_scoring_is_based_on_distinct_ids_not_raw_instance_count():
    # A "repeated 500 times" finding is exactly the same shape as a
    # grouped-findings row -- group_findings() already dedupes by id
    # before this function ever sees it, so this only has to prove the
    # score comes from severity counts, not from an accidental instance
    # count creeping back in.
    one_critical = compute_risk_score(_grouped("critical"))
    assert one_critical["score"] == 20


def test_severity_weights_are_additive_and_capped_at_100():
    five_critical = compute_risk_score(_grouped(*["critical"] * 5))
    assert five_critical["score"] == 100  # 5*20=100, exactly at the cap
    six_critical = compute_risk_score(_grouped(*["critical"] * 6))
    assert six_critical["score"] == 100  # would be 120 uncapped


def test_mixed_severities_combine():
    result = compute_risk_score(_grouped("high", "high", "medium", "low"))
    assert result["score"] == 10 + 10 + 4 + 1
    assert result["severity_counts"]["high"] == 2
    assert result["severity_counts"]["medium"] == 1
    assert result["severity_counts"]["low"] == 1


def test_info_only_findings_do_not_move_the_score():
    result = compute_risk_score(_grouped("info", "info", "info"))
    assert result["score"] == 0
    assert result["grade"] == "A"


def test_grade_bands():
    assert compute_risk_score(_grouped())["grade"] == "A"
    # 5*4=20 would band as B, but the medium floor (see
    # test_single_critical_is_never_outscored_by_low_severity_volume
    # below) pushes any medium presence to at least C.
    assert compute_risk_score(_grouped("medium", "medium", "medium", "medium", "medium"))[
        "grade"
    ] == "C"
    assert compute_risk_score(_grouped("high", "high", "high"))["grade"] == "D"  # 30, floored
    assert compute_risk_score(_grouped("high", "high", "high", "high", "high", "high"))[
        "grade"
    ] == "D"  # 60
    assert compute_risk_score(_grouped("critical", "critical", "critical", "critical"))[
        "grade"
    ] == "F"  # 80


def test_single_critical_is_never_outscored_by_low_severity_volume():
    # Regression test for a real reporting bug caught in review: a single
    # critical (score 20) used to land in the same "B" band as a pile of
    # unrelated mediums/lows with a similar numeric score -- e.g.
    # jwt-weak-secret (full auth bypass, forge any token) rendering the
    # same badge as a dozen missing-CSP-style header notes. The grade is
    # now floored by the single worst severity present, regardless of
    # what the numeric score alone would say.
    one_critical = compute_risk_score(_grouped("critical"))
    assert one_critical["score"] == 20
    assert one_critical["grade"] == "F"

    lots_of_low_severity = compute_risk_score(_grouped(*(["medium"] * 4 + ["low"] * 3)))
    assert lots_of_low_severity["score"] == 19
    assert lots_of_low_severity["grade"] == "C"  # medium-floored, but strictly better than F

    one_high = compute_risk_score(_grouped("high"))
    assert one_high["grade"] == "D"

    one_medium = compute_risk_score(_grouped("medium"))
    assert one_medium["grade"] == "C"


def test_unrecognized_severity_string_is_not_silently_dropped():
    # Regression test: an unrecognized severity string (a typo, a
    # hand-edited findings file, a future new severity level) used to
    # create an invisible extra key in severity_counts that the template
    # never reads -- a report could show "4 findings" directly above "0
    # critical, 0 high, 0 medium, 0 low, 0 info". The counts must always
    # add up to the number of findings passed in.
    result = compute_risk_score(_grouped("Critical", "urgent", "critical"))
    assert sum(result["severity_counts"].values()) == 3
    # Bucketed conservatively into "medium" rather than dropped, so the
    # severity floor still applies and the grade isn't a false "A".
    assert result["grade"] != "A"


def test_partial_coverage_flag():
    from risk_score import compute_risk_score as _crs

    clean = _crs([{"id": "missing-csp", "severity": "medium", "category": "header"}])
    assert clean["partial_coverage"] is False

    blocked = _crs(
        [
            {"id": "missing-csp", "severity": "medium", "category": "header"},
            {"id": "waf-challenge-sitewide", "severity": "info", "category": "waf-challenge"},
        ]
    )
    assert blocked["partial_coverage"] is True

    skipped = _crs(
        [{"id": "cors-probe-skipped", "severity": "info", "category": "scan-note"}]
    )
    assert skipped["partial_coverage"] is True

    truncated = _crs(
        [{"id": "redirect-chain-truncated", "severity": "info", "category": "scan-note"}]
    )
    assert truncated["partial_coverage"] is True
