from __future__ import annotations

from shroodler.waf_coverage import waf_coverage, waf_coverage_regression


def _doc(pages, challenged_urls):
    return {
        "target": "http://x",
        "pages": [{"url": u} for u in pages],
        "findings": [
            {
                "id": "waf-challenge-detected",
                "severity": "info",
                "category": "waf-challenge",
                "url": u,
                "description": "d",
                "evidence": None,
            }
            for u in challenged_urls
        ],
    }


def test_coverage_is_fraction_of_challenged_pages():
    doc = _doc(["http://x/a", "http://x/b", "http://x/c", "http://x/d"], ["http://x/a", "http://x/b"])
    assert waf_coverage(doc) == 0.5


def test_coverage_zero_when_no_pages():
    assert waf_coverage({"pages": [], "findings": []}) == 0.0


def test_coverage_zero_when_no_challenges():
    doc = _doc(["http://x/a"], [])
    assert waf_coverage(doc) == 0.0


def test_coverage_full_when_all_challenged():
    doc = _doc(["http://x/a"], ["http://x/a"])
    assert waf_coverage(doc) == 1.0


def test_regression_none_when_coverage_improves():
    older = _doc(["http://x/a", "http://x/b"], [])
    newer = _doc(["http://x/a", "http://x/b"], ["http://x/a", "http://x/b"])
    assert waf_coverage_regression(older, newer) is None


def test_regression_none_when_drop_within_threshold():
    older = _doc(["http://x/a", "http://x/b"], ["http://x/a", "http://x/b"])
    newer = _doc(["http://x/a", "http://x/b"], ["http://x/a"])
    # 1.0 -> 0.5 is a 0.5 drop, above default 0.2 threshold -- use a
    # generous threshold to confirm the "within threshold" path.
    assert waf_coverage_regression(older, newer, drop_threshold=0.6) is None


def test_regression_flagged_on_significant_drop():
    older = _doc(["http://x/a", "http://x/b"], ["http://x/a", "http://x/b"])
    newer = _doc(["http://x/a", "http://x/b"], [])
    finding = waf_coverage_regression(older, newer)
    assert finding is not None
    assert finding["id"] == "waf-coverage-drop"
    assert finding["category"] == "waf-challenge"
    assert finding["severity"] == "critical"


def test_severity_scales_with_drop_magnitude():
    # 20 pages so percentage-point drops land cleanly on tier boundaries.
    pages = [f"http://x/{i}" for i in range(20)]
    older = _doc(pages, pages)  # 100% coverage

    newer_medium_drop = _doc(pages, pages[:15])  # 75% coverage, 0.25 drop -> medium
    f_medium = waf_coverage_regression(older, newer_medium_drop)
    assert f_medium["severity"] == "medium"

    newer_high_drop = _doc(pages, pages[:12])  # 60% coverage, 0.40 drop -> high
    f_high = waf_coverage_regression(older, newer_high_drop)
    assert f_high["severity"] == "high"


def test_mismatched_page_counts_downgrade_severity_and_are_disclosed():
    # Older scan blocked to 5 pages, all challenged (100%); newer scan
    # reaches 50 pages (WAF reconfigured or crawler improved), 25
    # challenged (50%) -- a "50-point drop" by the raw fraction alone,
    # but arguably an improvement given 5x more pages triggered the WAF
    # in absolute terms. Must be disclosed, not silently reported as a
    # confident critical/high regression.
    older = _doc([f"http://x/{i}" for i in range(5)], [f"http://x/{i}" for i in range(5)])
    newer = _doc([f"http://x/{i}" for i in range(50)], [f"http://x/{i}" for i in range(25)])
    finding = waf_coverage_regression(older, newer)
    assert finding is not None
    assert finding["severity"] == "medium"
    assert finding["page_count_mismatch"] is True
    assert "5 pages" in finding["description"]
    assert "50 pages" in finding["description"]
    assert "may not be meaningful" in finding["description"]


def test_comparable_page_counts_are_not_flagged_as_mismatched():
    pages = [f"http://x/{i}" for i in range(20)]
    older = _doc(pages, pages)
    newer = _doc(pages, pages[:12])
    finding = waf_coverage_regression(older, newer)
    assert finding["page_count_mismatch"] is False
    assert "20 pages" in finding["evidence"]
