"""Tests for the evaluation harness scoring."""

from __future__ import annotations

from shroodler import eval_harness as ev


def _f(fid, url):
    return {"id": fid, "url": url}


EXPECTED = [
    _f("sqli", "http://t/api/items?id=1"),
    _f("xss", "http://t/search?q=a"),
    _f("idor", "http://t/api/users/5"),
]


def test_perfect_score():
    card = ev.score(EXPECTED, EXPECTED)
    assert card.true_positives == 3
    assert card.false_positives == 0
    assert card.false_negatives == 0
    assert card.precision == 1.0
    assert card.recall == 1.0
    assert card.f1 == 1.0


def test_partial_with_a_false_positive():
    actual = [
        _f("sqli", "http://t/api/items?id=9"),  # matches on path, query differs
        _f("xss", "http://t/search?q=b"),
        _f("bogus", "http://t/health"),
    ]
    card = ev.score(actual, EXPECTED)
    assert card.true_positives == 2
    assert card.false_positives == 1
    assert card.false_negatives == 1
    assert "bogus@/health" in card.unexpected
    assert "idor@/api/users/5" in card.missed
    assert round(card.precision, 2) == 0.67
    assert round(card.recall, 2) == 0.67


def test_matching_ignores_query_string():
    actual = [_f("sqli", "http://t/api/items?id=999&x=1")]
    card = ev.score(actual, [_f("sqli", "http://t/api/items?id=1")])
    assert card.true_positives == 1


def test_extract_findings_from_various_shapes():
    assert ev.extract_findings([_f("a", "u")]) == [_f("a", "u")]
    assert ev.extract_findings({"findings": [_f("a", "u")]}) == [_f("a", "u")]
    assert ev.extract_findings({"summary": [_f("a", "u")]}) == [_f("a", "u")]
    assert ev.extract_findings({"expected": [_f("a", "u")]}) == [_f("a", "u")]
    assert ev.extract_findings("garbage") == []


def test_cost_and_iterations_carry_from_doc():
    doc = {"iterations": 14, "cost_usd": 0.03, "findings": [_f("sqli", "http://t/api/items?id=1")]}
    card = ev.score(doc, EXPECTED)
    assert card.iterations == 14
    assert card.cost_usd == 0.03


def test_explicit_cost_overrides_doc():
    doc = {"cost_usd": 0.03, "findings": []}
    card = ev.score(doc, EXPECTED, cost_usd=0.9, iterations=3)
    assert card.cost_usd == 0.9
    assert card.iterations == 3


def test_compare_ab_delta():
    off = ev.score([_f("sqli", "http://t/api/items?id=1")], EXPECTED, label="off")
    on = ev.score(
        [_f("sqli", "http://t/api/items?id=1"), _f("xss", "http://t/search?q=z")],
        EXPECTED,
        label="on",
    )
    comp = ev.compare(off, on)
    assert comp["delta_true_positives"] == 1
    assert comp["delta_recall"] > 0
    assert "xss@/search" in comp["newly_found"]


def test_empty_actual_is_zero_precision_and_recall():
    card = ev.score([], EXPECTED)
    assert card.true_positives == 0
    assert card.precision == 0.0
    assert card.recall == 0.0
    assert card.f1 == 0.0


def test_format_scorecard_is_readable():
    card = ev.score(EXPECTED, EXPECTED, label="app1")
    text = ev.format_scorecard(card)
    assert "app1" in text
    assert "recall" in text
    assert "100.00%" in text


def test_cmd_eval_prints_scorecard(tmp_path, capsys):
    import argparse
    import json

    from shroodler.cli import cmd_eval

    (tmp_path / "exp.json").write_text(json.dumps({"findings": EXPECTED}))
    (tmp_path / "act.json").write_text(
        json.dumps({"cost_usd": 0.02, "iterations": 9, "findings": EXPECTED})
    )
    ns = argparse.Namespace(
        actual=str(tmp_path / "act.json"),
        expected=str(tmp_path / "exp.json"),
        baseline=None,
        label="app1",
        json=False,
    )
    assert cmd_eval(ns) == 0
    out = capsys.readouterr().out
    assert "recall" in out and "100.00%" in out


def test_cmd_eval_ab_baseline(tmp_path, capsys):
    import argparse
    import json

    from shroodler.cli import cmd_eval

    (tmp_path / "exp.json").write_text(json.dumps({"findings": EXPECTED}))
    (tmp_path / "on.json").write_text(json.dumps({"findings": EXPECTED[:2]}))
    (tmp_path / "off.json").write_text(json.dumps({"findings": EXPECTED[:1]}))
    ns = argparse.Namespace(
        actual=str(tmp_path / "on.json"),
        expected=str(tmp_path / "exp.json"),
        baseline=str(tmp_path / "off.json"),
        label="on",
        json=True,
    )
    assert cmd_eval(ns) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["comparison"]["delta_true_positives"] == 1
