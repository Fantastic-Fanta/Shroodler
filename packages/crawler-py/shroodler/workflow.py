"""Stateful-workflow bypass testing on top of the attack-chain executor.

A human walks a multi-step flow (cart -> checkout -> confirm) and asks "what if
I skip a step, or replay the final action?". This takes a baseline workflow
(an ``AttackChain`` -- from a chain-spec, a capture, or a built-in) that
succeeds end-to-end, then runs mutations of it:

* skip-step -- drop one prerequisite step and see if the target action still
  succeeds (direct access to a later step / missing workflow enforcement);
* replay-target -- repeat the final action and see if it succeeds twice
  (single-use / idempotency not enforced).

Reuses ``run_chain`` for execution (injectable for tests). Findings are
heuristic leads: a skipped step that was merely navigational is not a bug, so
each is flagged for a human to confirm the skipped step was a required gate.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable
from typing import Any

from shroodler.attack_chain import AttackChain, ChainStep, run_chain
from shroodler.models import Finding

RunFn = Callable[..., dict[str, Any]]


def _chain_with_steps(base: AttackChain, steps: list[ChainStep]) -> AttackChain:
    return dataclasses.replace(base, steps=list(steps))


def mutate_workflow(chain: AttackChain) -> list[tuple[str, AttackChain]]:
    """Generate (label, variant) bypass mutations of a baseline workflow."""
    steps = list(chain.steps or [])
    out: list[tuple[str, AttackChain]] = []
    if len(steps) < 2:
        return out
    # Skip each prerequisite step (never the final/target step), keep the rest.
    for i in range(len(steps) - 1):
        variant_steps = steps[:i] + steps[i + 1 :]
        out.append((f"skip-step:{steps[i].id}", _chain_with_steps(chain, variant_steps)))
    # Replay the final action once more.
    out.append(("replay-target", _chain_with_steps(chain, steps + [steps[-1]])))
    return out


def _succeeded(result: dict[str, Any]) -> bool:
    """A chain run completed end-to-end and its success_condition held."""
    if not isinstance(result, dict):
        return False
    if result.get("stopped_at"):
        return False
    return bool(result.get("findings"))


def _finding(fid: str, url: str, desc: str, evidence: str) -> Finding:
    return Finding(
        id=fid,
        severity="medium",  # type: ignore[arg-type]
        category="payload",
        url=url,
        description=desc,
        evidence=evidence,
        confidence="heuristic",  # type: ignore[arg-type]
    )


def run_workflow_mutations(
    baseline: AttackChain,
    *,
    config: Any = None,
    pacer: Any = None,
    client: Any = None,
    run: RunFn | None = None,
) -> list[Finding]:
    """Run the baseline workflow, then its bypass mutations; flag ones that still
    succeed. Bails if the baseline does not complete (nothing to bypass)."""
    runner = run or run_chain
    base = runner(baseline, config=config, pacer=pacer, client=client)
    if not _succeeded(base):
        return []  # the legitimate flow does not complete; cannot test a bypass

    target_url = baseline.steps[-1].url if baseline.steps else ""
    findings: list[Finding] = []
    for label, variant in mutate_workflow(baseline):
        result = runner(variant, config=config, pacer=pacer, client=client)
        if not _succeeded(result):
            continue
        if label.startswith("skip-step:"):
            skipped = label.split(":", 1)[1]
            findings.append(
                _finding(
                    "workflow-step-skip",
                    target_url,
                    (
                        f"The workflow {baseline.name!r} completed its final action "
                        f"without the step {skipped!r}. If that step is a required "
                        "gate (payment, approval, verification), it is not enforced "
                        "server-side."
                    ),
                    f"workflow={baseline.name} skipped={skipped}",
                )
            )
        elif label == "replay-target":
            findings.append(
                _finding(
                    "workflow-replay",
                    target_url,
                    (
                        f"The final action of workflow {baseline.name!r} succeeded "
                        "again on replay; a single-use/idempotency check may be "
                        "missing."
                    ),
                    f"workflow={baseline.name} replay=target",
                )
            )
    return findings
