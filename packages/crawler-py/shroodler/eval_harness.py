"""Evaluation harness: score a scan against curated ground truth.

Answers the only question that makes "smarter" meaningful: does a run find
the real bugs (recall) without crying wolf (precision), and at what cost?

A run is scored against an expected-findings file — the curated ground truth
for a target. Matching reuses the same (id, path) key the diff/gate command
uses, so a finding counts as found when its id and URL path match an expected
entry. The harness also carries through cost and iteration counts when the
input is an agent result, and can diff two runs for an A/B comparison (LLM
tools on vs off).

Pure and dependency-light: it scores dicts, so it is fully unit-testable
without a live target. The live run against the docker apps is driven by the
`shroodler eval` CLI command.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from shroodler.diffcmd import finding_key


@dataclass
class Scorecard:
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    matched: list[str] = field(default_factory=list)
    unexpected: list[str] = field(default_factory=list)
    missed: list[str] = field(default_factory=list)
    cost_usd: float | None = None
    iterations: int | None = None
    label: str = ""

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return (2 * p * r / (p + r)) if (p + r) else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "matched": self.matched,
            "unexpected": self.unexpected,
            "missed": self.missed,
            "cost_usd": self.cost_usd,
            "iterations": self.iterations,
        }


def _key_str(item: dict) -> str:
    fid, path = finding_key(item)
    return f"{fid}@{path or '/'}"


def extract_findings(doc: Any) -> list[dict]:
    """Pull a findings list out of a scan JSON, agent result, or raw list."""
    if isinstance(doc, list):
        return [f for f in doc if isinstance(f, dict)]
    if isinstance(doc, dict):
        for key in ("findings", "summary", "expected", "expected_findings"):
            val = doc.get(key)
            if isinstance(val, list):
                return [f for f in val if isinstance(f, dict)]
    return []


def _run_meta(doc: Any) -> tuple[float | None, int | None]:
    if not isinstance(doc, dict):
        return None, None
    cost = doc.get("cost_usd")
    if cost is None:
        cost = (doc.get("llm") or {}).get("cost_usd") if isinstance(doc.get("llm"), dict) else None
    iters = doc.get("iterations")
    try:
        cost = float(cost) if cost is not None else None
    except (TypeError, ValueError):
        cost = None
    try:
        iters = int(iters) if iters is not None else None
    except (TypeError, ValueError):
        iters = None
    return cost, iters


def score(
    actual: Any,
    expected: Any,
    *,
    label: str = "",
    cost_usd: float | None = None,
    iterations: int | None = None,
) -> Scorecard:
    """Score `actual` findings against `expected` ground truth.

    `actual` / `expected` may be findings lists or full scan/agent docs.
    """
    actual_findings = extract_findings(actual)
    expected_findings = extract_findings(expected)
    actual_keys = {_key_str(f) for f in actual_findings}
    expected_keys = {_key_str(f) for f in expected_findings}
    matched = sorted(actual_keys & expected_keys)
    unexpected = sorted(actual_keys - expected_keys)
    missed = sorted(expected_keys - actual_keys)
    doc_cost, doc_iters = _run_meta(actual)
    return Scorecard(
        true_positives=len(matched),
        false_positives=len(unexpected),
        false_negatives=len(missed),
        matched=matched,
        unexpected=unexpected,
        missed=missed,
        cost_usd=cost_usd if cost_usd is not None else doc_cost,
        iterations=iterations if iterations is not None else doc_iters,
        label=label,
    )


def compare(baseline: Scorecard, candidate: Scorecard) -> dict[str, Any]:
    """A/B delta between two runs (e.g. LLM tools off vs on)."""
    return {
        "baseline": baseline.label or "baseline",
        "candidate": candidate.label or "candidate",
        "delta_true_positives": candidate.true_positives - baseline.true_positives,
        "delta_false_positives": candidate.false_positives - baseline.false_positives,
        "delta_precision": round(candidate.precision - baseline.precision, 4),
        "delta_recall": round(candidate.recall - baseline.recall, 4),
        "delta_f1": round(candidate.f1 - baseline.f1, 4),
        "newly_found": sorted(set(candidate.matched) - set(baseline.matched)),
        "newly_missed": sorted(set(baseline.matched) - set(candidate.matched)),
    }


def load_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def format_scorecard(card: Scorecard) -> str:
    lines = [
        f"Scorecard{f' [{card.label}]' if card.label else ''}",
        f"  true positives : {card.true_positives}",
        f"  false positives: {card.false_positives}",
        f"  missed         : {card.false_negatives}",
        f"  precision      : {card.precision:.2%}",
        f"  recall         : {card.recall:.2%}",
        f"  f1             : {card.f1:.2%}",
    ]
    if card.cost_usd is not None:
        lines.append(f"  cost           : ${card.cost_usd:.4f}")
    if card.iterations is not None:
        lines.append(f"  iterations     : {card.iterations}")
    if card.unexpected:
        lines.append(f"  false positives: {', '.join(card.unexpected[:10])}")
    if card.missed:
        lines.append(f"  missed         : {', '.join(card.missed[:10])}")
    return "\n".join(lines)
