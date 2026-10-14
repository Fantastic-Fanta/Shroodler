from __future__ import annotations

from shroodler.eval_harness import Scorecard
from shroodler.soak import (
    aggregate,
    baseline_from,
    detect_regressions,
    render_markdown,
)


def _card(matched: list[str], missed: list[str], unexpected: list[str], *, cost=None) -> Scorecard:
    return Scorecard(
        true_positives=len(matched),
        false_positives=len(unexpected),
        false_negatives=len(missed),
        matched=matched,
        unexpected=unexpected,
        missed=missed,
        cost_usd=cost,
    )


def test_aggregate_stable_runs_are_not_flaky():
    cards = [_card(["a@/", "b@/"], [], []) for _ in range(3)]
    stat = aggregate("app1", cards)
    assert stat.runs == 3
    assert stat.recall_mean == 1.0
    assert stat.recall_stdev == 0.0
    assert stat.fp_mean == 0.0
    assert stat.flaky is False
    assert stat.sometimes_missed == []


def test_aggregate_flags_recall_wobble():
    good = _card(["a@/", "b@/", "c@/"], [], [])  # recall 1.0
    bad = _card(["a@/", "b@/"], ["c@/"], [])  # recall 0.667
    stat = aggregate("app2", [good, bad])
    assert stat.recall_max == 1.0
    assert round(stat.recall_min, 3) == 0.667
    assert stat.recall_stdev > 0.0
    assert stat.flaky is True
    assert stat.sometimes_missed == ["c@/"]


def test_aggregate_flags_false_positive_wobble():
    clean = _card(["a@/"], [], [])
    noisy = _card(["a@/"], [], ["x@/"])
    stat = aggregate("app3", [clean, noisy])
    assert stat.fp_mean == 0.5
    assert stat.fp_max == 1
    assert stat.flaky is True
    assert stat.false_positives == ["x@/"]


def test_aggregate_cost_mean_ignores_missing():
    cards = [_card(["a@/"], [], [], cost=0.0), _card(["a@/"], [], [], cost=None)]
    stat = aggregate("app4", cards)
    assert stat.cost_mean == 0.0  # only the one present cost counts


def test_detect_regressions_recall_drop_and_fp_rise():
    recall_regressed = aggregate("a", [_card(["x@/"], ["y@/", "z@/"], [])])  # recall ~0.33
    fp_regressed = aggregate("b", [_card(["x@/"], [], ["n1@/", "n2@/"])])  # fp 2
    steady = aggregate("c", [_card(["x@/"], [], [])])  # recall 1.0, fp 0
    baseline = {
        "a": {"recall_mean": 1.0, "fp_mean": 0.0},
        "b": {"recall_mean": 1.0, "fp_mean": 0.0},
        "c": {"recall_mean": 1.0, "fp_mean": 0.0},
    }
    msgs = detect_regressions([recall_regressed, fp_regressed, steady], baseline)
    joined = "\n".join(msgs)
    assert "a: recall" in joined
    assert "b: false positives" in joined
    assert "c:" not in joined


def test_detect_regressions_without_baseline_is_empty():
    stat = aggregate("a", [_card(["x@/"], ["y@/"], [])])
    assert detect_regressions([stat], None) == []


def test_baseline_from_roundtrips_into_detect():
    stats = [aggregate("a", [_card(["x@/"], [], [])])]
    base = baseline_from(stats)
    assert base["a"]["recall_mean"] == 1.0
    # Same numbers compared against themselves -> no regression.
    assert detect_regressions(stats, base) == []


def test_render_markdown_includes_table_and_regression_section():
    stats = [aggregate("app5", [_card(["a@/", "b@/"], ["c@/"], [])])]
    md = render_markdown(stats, ["app5: recall 66.7% down from 100.0% baseline"], title="Nightly")
    assert "# Nightly" in md
    assert "## Regressions (1)" in md
    assert "| app5 |" in md
    assert "Coverage gaps" in md  # recall_max < 1.0


def test_render_markdown_no_regressions_line():
    stats = [aggregate("app5", [_card(["a@/"], [], [])])]
    md = render_markdown(stats, [])
    assert "No regressions vs baseline." in md
