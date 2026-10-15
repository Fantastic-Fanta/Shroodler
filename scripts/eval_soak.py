#!/usr/bin/env python3
"""Eval soak: repeat each scored target run N times and summarise its stability.

A single `shroodler eval` scores one run; a soak repeats it so flaky recall and
drift against a committed baseline become visible. Meant to be left running
(e.g. overnight) against the local target apps.

Run from anywhere with the repo venv:
  /Users/manta/Shroodler/.venv/bin/python /Users/manta/Shroodler/scripts/eval_soak.py \
      --manifest scripts/soak-manifest.example.json --out soak-report.md

Manifest (JSON):
  {
    "title": "nightly soak",
    "targets": [
      {"label": "app5", "expected": "packages/target-apps/app5-injectable/expected_findings.json",
       "command": ["shroodler", "payload", "--target", "http://127.0.0.1:8087", ...],
       "repeat": 5},
      {"label": "app1-replay", "expected": "expected.json",
       "runs": ["run1.json", "run2.json"]}
    ]
  }

Each target is scored `repeat` times (live `command` capturing JSON on stdout)
or from pre-collected `runs` files. Exits 1 if a regression vs --baseline is
found (unless --no-gate), 2 on a usage/IO error, 0 otherwise.

This is an eval/ops script, not a pytest test.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from shroodler import eval_harness as ev
from shroodler import soak


def _load_json(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _run_command(command: list[str], timeout: float) -> dict[str, Any]:
    """Run a scan command and parse its stdout as the actual-run JSON."""
    proc = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    out = proc.stdout.strip()
    if not out:
        raise ValueError(
            f"command produced no JSON on stdout (exit {proc.returncode}): "
            f"{proc.stderr.strip()[:400]}"
        )
    try:
        return json.loads(out)
    except json.JSONDecodeError as exc:
        # Some commands print a human line before the JSON; take the last {...} block.
        start = out.rfind("\n{")
        if start != -1:
            try:
                return json.loads(out[start + 1 :])
            except json.JSONDecodeError:
                pass
        raise ValueError(f"command stdout was not JSON: {exc}") from exc


def _scorecards_for_target(target: dict[str, Any], timeout: float) -> list[ev.Scorecard]:
    label = str(target.get("label") or "target")
    expected = _load_json(str(target["expected"]))
    cards: list[ev.Scorecard] = []
    runs = target.get("runs")
    if isinstance(runs, list) and runs:
        for i, run_path in enumerate(runs):
            actual = _load_json(str(run_path))
            cards.append(ev.score(actual, expected, label=f"{label}#{i}"))
        return cards
    command = target.get("command")
    if not isinstance(command, list) or not command:
        raise ValueError(f"target {label!r} needs either 'runs' or 'command'")
    repeat = int(target.get("repeat", 3) or 3)
    for i in range(max(1, repeat)):
        actual = _run_command([str(c) for c in command], timeout)
        cards.append(ev.score(actual, expected, label=f"{label}#{i}"))
    return cards


def run_soak(manifest: dict[str, Any], *, timeout: float) -> list[soak.SoakStats]:
    stats: list[soak.SoakStats] = []
    for target in manifest.get("targets", []):
        if not isinstance(target, dict):
            continue
        label = str(target.get("label") or "target")
        cards = _scorecards_for_target(target, timeout)
        stats.append(soak.aggregate(label, cards))
    return stats


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Repeat scored eval runs and summarise stability.")
    parser.add_argument("--manifest", required=True, help="Soak manifest JSON (see module docstring)")
    parser.add_argument("--baseline", default=None, help="Baseline snapshot JSON to compare against")
    parser.add_argument("--out", default=None, help="Write the Markdown report here (else stdout)")
    parser.add_argument("--json-out", default=None, help="Write the full results as JSON here")
    parser.add_argument(
        "--update-baseline",
        default=None,
        metavar="JSON",
        help="Write a fresh baseline snapshot from this run to this path",
    )
    parser.add_argument("--timeout", type=float, default=1800.0, help="Per-run command timeout (s)")
    parser.add_argument(
        "--no-gate",
        action="store_true",
        help="Do not exit nonzero when a regression vs --baseline is found",
    )
    args = parser.parse_args(argv)

    try:
        manifest = _load_json(args.manifest)
    except (OSError, ValueError) as exc:
        print(f"error: cannot read manifest: {exc}", file=sys.stderr)
        return 2
    try:
        stats = run_soak(manifest, timeout=args.timeout)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    baseline = None
    if args.baseline:
        try:
            baseline = _load_json(args.baseline)
        except (OSError, ValueError) as exc:
            print(f"error: cannot read baseline: {exc}", file=sys.stderr)
            return 2

    regressions = soak.detect_regressions(stats, baseline)
    title = str(manifest.get("title") or "Eval soak")
    report = soak.render_markdown(stats, regressions, title=title)

    if args.out:
        Path(args.out).write_text(report, encoding="utf-8")
        print(f"wrote report to {args.out}", file=sys.stderr)
    else:
        print(report)

    if args.json_out:
        payload = {
            "title": title,
            "stats": [s.to_dict() for s in stats],
            "regressions": regressions,
        }
        Path(args.json_out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"wrote results to {args.json_out}", file=sys.stderr)

    if args.update_baseline:
        Path(args.update_baseline).write_text(
            json.dumps(soak.baseline_from(stats), indent=2), encoding="utf-8"
        )
        print(f"wrote baseline to {args.update_baseline}", file=sys.stderr)

    if regressions and not args.no_gate:
        print(f"regressions found: {len(regressions)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
