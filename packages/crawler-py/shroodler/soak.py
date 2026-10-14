"""Eval-soak aggregation: repeat a scored run many times and summarise it.

A single `shroodler eval` scores one run. A soak repeats that run N times per
target (and optionally per provider/config), so the thing it measures is not
one recall number but its *stability*: does recall wobble between runs (a
nondeterministic LLM verdict or a flaky probe), and has the mean drifted below
a committed baseline?

Pure and dependency-light on purpose: it aggregates `Scorecard`s, so the whole
thing is unit-testable without a live target. `scripts/eval_soak.py` drives the
live runs against the docker apps and feeds their scorecards in here.
"""

from __future__ import annotations

import statistics
from dataclasses import asdict, dataclass, field
from typing import Any

from shroodler.eval_harness import Scorecard


def _mean(values: list[float]) -> float:
    return float(statistics.mean(values)) if values else 0.0


def _stdev(values: list[float]) -> float:
    # Population stdev; 0 for a single run (no variance to report).
    return float(statistics.pstdev(values)) if len(values) > 1 else 0.0


@dataclass
class SoakStats:
    """Aggregate of repeated scorecards for one (target, config) label."""

    label: str
    runs: int = 0
    recall_mean: float = 0.0
    recall_min: float = 0.0
    recall_max: float = 0.0
    recall_stdev: float = 0.0
    precision_mean: float = 0.0
    precision_min: float = 0.0
    precision_max: float = 0.0
    f1_mean: float = 0.0
    fp_mean: float = 0.0
    fp_max: int = 0
    cost_mean: float | None = None
    # Bugs missed in at least one run (recall instability or a hard miss).
    sometimes_missed: list[str] = field(default_factory=list)
    # False positives seen in at least one run.
    false_positives: list[str] = field(default_factory=list)

    @property
    def flaky(self) -> bool:
        """True when recall or false-positive count varied across runs."""
        return self.runs > 1 and (self.recall_stdev > 0.0 or self.fp_mean != self.fp_max)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["flaky"] = self.flaky
        return data


def aggregate(label: str, cards: list[Scorecard]) -> SoakStats:
    """Summarise repeated scorecards for one label."""
    if not cards:
        return SoakStats(label=label, runs=0)
    recalls = [c.recall for c in cards]
    precisions = [c.precision for c in cards]
    f1s = [c.f1 for c in cards]
    fps = [c.false_positives for c in cards]
    costs = [c.cost_usd for c in cards if c.cost_usd is not None]
    missed: set[str] = set()
    false_pos: set[str] = set()
    for card in cards:
        missed.update(card.missed)
        false_pos.update(card.unexpected)
    return SoakStats(
        label=label,
        runs=len(cards),
        recall_mean=round(_mean(recalls), 4),
        recall_min=round(min(recalls), 4),
        recall_max=round(max(recalls), 4),
        recall_stdev=round(_stdev(recalls), 4),
        precision_mean=round(_mean(precisions), 4),
        precision_min=round(min(precisions), 4),
        precision_max=round(max(precisions), 4),
        f1_mean=round(_mean(f1s), 4),
        fp_mean=round(_mean([float(x) for x in fps]), 4),
        fp_max=max(fps),
        cost_mean=round(_mean(costs), 6) if costs else None,
        sometimes_missed=sorted(missed),
        false_positives=sorted(false_pos),
    )


def baseline_from(stats: list[SoakStats]) -> dict[str, dict[str, float]]:
    """A compact baseline snapshot (per label) to commit and compare against."""
    return {
        s.label: {"recall_mean": s.recall_mean, "fp_mean": s.fp_mean}
        for s in stats
    }


def detect_regressions(
    stats: list[SoakStats],
    baseline: dict[str, Any] | None,
    *,
    recall_drop: float = 0.05,
    fp_rise: float = 0.5,
) -> list[str]:
    """Flag labels whose mean recall dropped or false positives rose vs baseline."""
    if not baseline:
        return []
    out: list[str] = []
    for stat in stats:
        base = baseline.get(stat.label)
        if not isinstance(base, dict):
            continue
        base_recall = float(base.get("recall_mean", 0.0) or 0.0)
        base_fp = float(base.get("fp_mean", 0.0) or 0.0)
        if stat.recall_mean < base_recall - recall_drop:
            out.append(
                f"{stat.label}: recall {stat.recall_mean:.2%} down from "
                f"{base_recall:.2%} baseline (-{base_recall - stat.recall_mean:.2%})"
            )
        if stat.fp_mean > base_fp + fp_rise:
            out.append(
                f"{stat.label}: false positives {stat.fp_mean:.2f} up from "
                f"{base_fp:.2f} baseline (+{stat.fp_mean - base_fp:.2f})"
            )
    return out


def _pct(value: float) -> str:
    return f"{value:.1%}"


def render_markdown(
    stats: list[SoakStats],
    regressions: list[str] | None = None,
    *,
    title: str = "Eval soak",
) -> str:
    """Render the soak matrix and any regressions as Markdown."""
    lines: list[str] = [f"# {title}", ""]
    regressions = regressions or []
    if regressions:
        lines.append(f"## Regressions ({len(regressions)})")
        lines.extend(f"- {msg}" for msg in regressions)
        lines.append("")
    else:
        lines.append("No regressions vs baseline.")
        lines.append("")

    lines.append("## Results")
    lines.append("")
    lines.append("| Target / config | runs | recall (mean) | recall range | precision | FP (mean/max) | flaky |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- |")
    for stat in stats:
        rng = (
            f"{_pct(stat.recall_min)}–{_pct(stat.recall_max)}"
            if stat.runs > 1
            else "—"
        )
        lines.append(
            f"| {stat.label} | {stat.runs} | {_pct(stat.recall_mean)} | {rng} | "
            f"{_pct(stat.precision_mean)} | {stat.fp_mean:.1f}/{stat.fp_max} | "
            f"{'yes' if stat.flaky else 'no'} |"
        )
    lines.append("")

    flaky = [s for s in stats if s.flaky]
    if flaky:
        lines.append("## Flaky targets (recall or FP varied across runs)")
        for stat in flaky:
            missed = ", ".join(stat.sometimes_missed[:10]) or "none"
            lines.append(
                f"- **{stat.label}**: recall {stat.recall_stdev:.3f} stdev; "
                f"sometimes-missed: {missed}"
            )
        lines.append("")

    hard_miss = [s for s in stats if s.recall_max < 1.0]
    if hard_miss:
        lines.append("## Coverage gaps (never 100% recall in any run)")
        for stat in hard_miss:
            missed = ", ".join(stat.sometimes_missed[:10]) or "none"
            lines.append(f"- **{stat.label}**: best recall {_pct(stat.recall_max)}; missed: {missed}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"
