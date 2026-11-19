"""Infer multi-step state-changing workflows and their sequence invariants.

Per-object (ownership) and per-surface (privilege) authorization are point
checks. The bugs a human still finds that a scanner misses are *stateful*: a
checkout you can confirm without paying, an invite you can accept twice, an
approval step you can reach out of order. Those live in workflows -- ordered
sequences of state-changing steps -- not in any single endpoint.

This module takes the first step toward reasoning about them. From a scan
document's forms (the state-changing steps) it groups the mutating steps of a
flow and orders them by their action verbs, then states the invariant whose
violation is a business-logic bug: a later step must not succeed without the
earlier ones (broken sequence / step-skipping), and a step that commits an
effect should not be blindly replayable.

It is deliberately conservative and explainable -- whole-segment grouping and a
small verb-rank table, not graph guesswork -- because a noisy business-logic
lead costs more trust than it is worth. Everything here is derived from the scan
document; it issues no requests. Apache-2.0, Shroodler's own code.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse

_READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# Verb tokens that order steps within a flow (lower rank = earlier). A step is
# ranked by the earliest-ranked token found in its action path.
_STEP_RANK: list[tuple[int, frozenset[str]]] = [
    (
        0,
        frozenset(
            {"start", "begin", "create", "add", "new", "register", "signup", "cart", "init"}
        ),
    ),
    (1, frozenset({"update", "edit", "modify", "apply", "set", "address", "shipping"})),
    (2, frozenset({"review", "validate", "verify", "preview"})),
    (
        3,
        frozenset(
            {
                "confirm",
                "submit",
                "checkout",
                "pay",
                "payment",
                "purchase",
                "order",
                "place",
                "complete",
                "finalize",
                "finish",
                "approve",
                "accept",
            }
        ),
    ),
]
_DEFAULT_RANK = 1


@dataclass
class WorkflowStep:
    """One state-changing step of a workflow (a non-GET form submission)."""

    action: str
    method: str
    rank: int
    fields: list[str] = field(default_factory=list)


@dataclass
class Workflow:
    """An ordered group of state-changing steps that form one flow."""

    name: str
    steps: list[WorkflowStep] = field(default_factory=list)

    @property
    def terminal(self) -> WorkflowStep | None:
        return self.steps[-1] if self.steps else None


@dataclass
class WorkflowInvariant:
    kind: str  # "sequence"
    workflow: str
    statement: str
    test_hint: str


def _segments(url: str) -> list[str]:
    try:
        return [s for s in (urlparse(url).path or "").split("/") if s]
    except ValueError:
        return []


def _group_key(action: str) -> str:
    """The flow a step belongs to: its first meaningful path segment."""
    segs = _segments(action)
    return segs[0].lower() if segs else ""


def _step_rank(action: str) -> int:
    segs = {s.lower() for s in _segments(action)}
    for rank, tokens in _STEP_RANK:
        if segs & tokens:
            return rank
    return _DEFAULT_RANK


def _field_names(form: dict) -> list[str]:
    out: list[str] = []
    for fld in form.get("fields") or []:
        name = str((fld or {}).get("name") or "").strip()
        if name:
            out.append(name)
    return out


def infer_workflows(doc: dict) -> list[Workflow]:
    """Infer candidate workflows from a scan document's forms. Never raises.

    A workflow is a group of two or more distinct state-changing steps (non-GET
    form submissions) that share a leading path segment, ordered by action verb.
    A lone step is not a workflow and is dropped.
    """
    try:
        steps_by_group: dict[str, dict[tuple[str, str], WorkflowStep]] = {}
        for page in doc.get("pages") or []:
            base = str((page or {}).get("url") or "")
            for form in (page or {}).get("forms") or []:
                method = str((form or {}).get("method") or "GET").upper() or "GET"
                if method in _READ_METHODS:
                    continue
                action = str((form or {}).get("action") or "").strip() or base
                key = _group_key(action)
                if not key:
                    continue
                step = WorkflowStep(
                    action=action,
                    method=method,
                    rank=_step_rank(action),
                    fields=_field_names(form),
                )
                steps_by_group.setdefault(key, {})[(action, method)] = step

        workflows: list[Workflow] = []
        for key in sorted(steps_by_group):
            steps = list(steps_by_group[key].values())
            if len(steps) < 2:
                continue
            steps.sort(key=lambda s: (s.rank, s.action))
            workflows.append(Workflow(name=key, steps=steps))
        return workflows
    except Exception:  # noqa: BLE001 - inference must never break a run
        return []


def workflow_invariants(doc: dict) -> list[WorkflowInvariant]:
    """Sequence invariants for the inferred workflows (a violation is a bug)."""
    out: list[WorkflowInvariant] = []
    for wf in infer_workflows(doc):
        terminal = wf.terminal
        if terminal is None or terminal.rank == 0:
            # No clearly-terminal (commit) step -> no confident sequence claim.
            continue
        priors = ", ".join(s.action for s in wf.steps[:-1]) or "the earlier steps"
        out.append(
            WorkflowInvariant(
                kind="sequence",
                workflow=wf.name,
                statement=(
                    f"the {wf.name} flow's terminal step {terminal.action} "
                    f"({terminal.method}) should not succeed without completing "
                    f"{priors} first (broken sequence / step-skipping), and should "
                    "not be blindly replayable to double its effect"
                ),
                test_hint=(
                    f"submit {terminal.action} directly without the prior steps, "
                    "then replay it, as an authenticated user"
                ),
            )
        )
    return out


def summarize_workflows(doc: dict) -> str:
    """Render a WORKFLOWS block, or '' when nothing multi-step was inferred."""
    workflows = infer_workflows(doc)
    if not workflows:
        return ""
    lines = ["WORKFLOWS (inferred state-changing flows; verify, do not assume):"]
    for wf in workflows:
        chain = " -> ".join(f"{s.method} {s.action}" for s in wf.steps)
        lines.append(f"- {wf.name}: {chain}")
    invs = workflow_invariants(doc)
    if invs:
        lines.append("sequence invariants to check (a violation is a logic bug):")
        for inv in invs:
            lines.append(f"- {inv.statement} -> {inv.test_hint}")
    return "\n".join(lines)


def workflows_as_dicts(doc: dict) -> list[dict]:
    """Inferred workflows as plain dicts, for `workflows --json`."""
    out = []
    for wf in infer_workflows(doc):
        out.append(
            {
                "name": wf.name,
                "steps": [
                    {
                        "action": s.action,
                        "method": s.method,
                        "rank": s.rank,
                        "fields": list(s.fields),
                    }
                    for s in wf.steps
                ],
            }
        )
    return out
