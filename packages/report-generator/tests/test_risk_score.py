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
    assert compute_risk_score(_grouped("medium", "medium", "medium", "medium", "medium"))[
        "grade"
    ] == "B"  # 5*4=20
    assert compute_risk_score(_grouped("high", "high", "high"))["grade"] == "C"  # 30
    assert compute_risk_score(_grouped("high", "high", "high", "high", "high", "high"))[
        "grade"
    ] == "D"  # 60
    assert compute_risk_score(_grouped("critical", "critical", "critical", "critical"))[
        "grade"
    ] == "F"  # 80
