"""File or sync GitHub issues from scan findings.

`diff --gate` only fails a build; this turns new (id, path) pairs into
tickets, deduped by the same finding key, and can close them when a later
scan no longer reports the finding. Dry-run by default -- `--apply` is
required to call `gh`. Tests inject a fake backend; nothing here talks
to GitHub unless the operator asked.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from shroodler.diffcmd import diff_outcome, finding_key, load_json
from shroodler.sla import owner_for
from shroodler.suppress import filter_findings, path_of

DEFAULT_STATE = ".shroodler-tickets.json"
DEFAULT_LABEL = "shroodler"


def ticket_key(finding: dict) -> str:
    fid, path = finding_key(finding)
    return f"{fid}|{path}"


def issue_title(finding: dict) -> str:
    sev = finding.get("severity") or "info"
    fid = finding.get("id") or "finding"
    path = path_of(finding.get("url") or "")
    return f"[{sev}] {fid} at {path}"


def issue_body(finding: dict, *, owner: str = "") -> str:
    lines = [
        f"**id:** `{finding.get('id', '')}`",
        f"**severity:** {finding.get('severity', '')}",
        f"**category:** {finding.get('category', '')}",
        f"**url:** {finding.get('url', '')}",
        f"**confidence:** {finding.get('confidence') or '(unset)'}",
    ]
    if owner:
        lines.append(f"**owner:** {owner}")
    desc = (finding.get("description") or "").strip()
    if desc:
        lines.extend(["", desc])
    evidence = finding.get("evidence")
    if evidence:
        lines.extend(["", "```", str(evidence), "```"])
    lines.extend(
        [
            "",
            "---",
            "Opened by `shroodler ticket`. Dedup key: "
            f"`{ticket_key(finding)}`.",
        ]
    )
    return "\n".join(lines) + "\n"


@dataclass
class TicketRef:
    number: int
    url: str = ""


class TicketBackend(Protocol):
    def create(
        self, title: str, body: str, *, labels: list[str], assignee: str
    ) -> TicketRef: ...

    def close(self, number: int) -> None: ...


@dataclass
class MemoryBackend:
    """In-process backend for tests. Never talks to GitHub."""

    created: list[dict] = field(default_factory=list)
    closed: list[int] = field(default_factory=list)
    next_number: int = 1

    def create(
        self, title: str, body: str, *, labels: list[str], assignee: str
    ) -> TicketRef:
        number = self.next_number
        self.next_number += 1
        self.created.append(
            {"number": number, "title": title, "body": body, "labels": labels, "assignee": assignee}
        )
        return TicketRef(number=number, url=f"memory://issue/{number}")

    def close(self, number: int) -> None:
        self.closed.append(number)


class GhBackend:
    """Thin wrapper around the `gh` CLI. Not used unless `--apply`."""

    def __init__(
        self,
        *,
        repo: str | None = None,
        run=subprocess.run,
        gh: str = "gh",
    ) -> None:
        self.repo = repo
        self._run = run
        self.gh = gh

    def _exec(self, args: list[str]) -> str:
        cmd = [self.gh, *args]
        proc = self._run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip() or f"exit {proc.returncode}"
            raise RuntimeError(f"gh {' '.join(args)} failed: {err}")
        return proc.stdout or ""

    def create(
        self, title: str, body: str, *, labels: list[str], assignee: str
    ) -> TicketRef:
        args = ["issue", "create", "--title", title, "--body", body]
        if self.repo:
            args.extend(["--repo", self.repo])
        for label in labels:
            args.extend(["--label", label])
        if assignee:
            args.extend(["--assignee", assignee])
        out = self._exec(args).strip()
        number = _issue_number_from_gh_output(out)
        return TicketRef(number=number, url=out.splitlines()[-1].strip() if out else "")

    def close(self, number: int) -> None:
        args = ["issue", "close", str(number)]
        if self.repo:
            args.extend(["--repo", self.repo])
        self._exec(args)


def _issue_number_from_gh_output(text: str) -> int:
    for token in reversed(text.replace("\n", " ").split()):
        if "/issues/" in token:
            tail = token.rstrip("/").rsplit("/", 1)[-1]
            if tail.isdigit():
                return int(tail)
        if token.startswith("#") and token[1:].isdigit():
            return int(token[1:])
    raise RuntimeError(f"could not parse issue number from gh output: {text!r}")


def load_state(path: str | Path) -> dict[str, dict]:
    p = Path(path)
    if not p.is_file():
        return {}
    data = json.loads(p.read_text(encoding="utf-8"))
    issues = data.get("issues") if isinstance(data, dict) else None
    if not isinstance(issues, dict):
        return {}
    out: dict[str, dict] = {}
    for key, rec in issues.items():
        if isinstance(rec, dict) and rec.get("number") is not None:
            out[str(key)] = rec
    return out


def save_state(path: str | Path, issues: dict[str, dict]) -> None:
    Path(path).write_text(
        json.dumps({"issues": issues}, indent=2) + "\n", encoding="utf-8"
    )


def visible_findings(doc: dict, suppressions: list[dict] | None) -> list[dict]:
    return list(filter_findings(doc.get("findings") or [], suppressions or []))


def new_findings(
    current: dict,
    baseline: dict | None,
    *,
    suppressions: list[dict] | None = None,
) -> list[dict]:
    """Findings that would fail `diff --gate` (or every visible finding
    if no baseline was given)."""
    if baseline is None:
        return visible_findings(current, suppressions)
    return list(
        diff_outcome(current, baseline, gate=True, suppressions=suppressions).new_findings
    )


def resolved_keys(
    current: dict,
    state: dict[str, dict],
    *,
    suppressions: list[dict] | None = None,
) -> list[str]:
    present = {ticket_key(f) for f in visible_findings(current, suppressions)}
    return [key for key in state if key not in present]


@dataclass
class Plan:
    create: list[dict] = field(default_factory=list)
    close: list[dict] = field(default_factory=list)
    skip: list[dict] = field(default_factory=list)


def plan_tickets(
    current: dict,
    *,
    baseline: dict | None = None,
    state: dict[str, dict] | None = None,
    owners: list[dict] | None = None,
    suppressions: list[dict] | None = None,
    close_resolved: bool = False,
) -> Plan:
    state = state or {}
    owners = owners or []
    plan = Plan()
    for finding in new_findings(current, baseline, suppressions=suppressions):
        key = ticket_key(finding)
        owner = owner_for(finding, owners) if owners else ""
        rec = {
            "key": key,
            "title": issue_title(finding),
            "body": issue_body(finding, owner=owner),
            "owner": owner,
            "finding_id": finding.get("id"),
            "url": finding.get("url"),
        }
        if key in state:
            rec["issue"] = state[key]
            rec["reason"] = "already filed"
            plan.skip.append(rec)
            continue
        plan.create.append(rec)
    if close_resolved:
        for key in resolved_keys(current, state, suppressions=suppressions):
            rec = dict(state[key])
            rec["key"] = key
            rec["reason"] = "finding gone from current scan"
            plan.close.append(rec)
    return plan


def apply_plan(
    plan: Plan,
    backend: TicketBackend,
    state: dict[str, dict],
    *,
    label: str = DEFAULT_LABEL,
) -> dict[str, dict]:
    updated = dict(state)
    for rec in plan.create:
        ref = backend.create(
            rec["title"],
            rec["body"],
            labels=[label] if label else [],
            assignee=rec.get("owner") or "",
        )
        updated[rec["key"]] = {
            "number": ref.number,
            "url": ref.url,
            "title": rec["title"],
        }
        rec["issue"] = updated[rec["key"]]
    for rec in plan.close:
        number = int(rec["number"])
        backend.close(number)
        updated.pop(rec["key"], None)
    return updated


def plan_to_dict(plan: Plan) -> dict:
    return {
        "create": plan.create,
        "close": plan.close,
        "skip": plan.skip,
    }


def run_ticket_command(
    *,
    findings_path: str,
    baseline_path: str | None = None,
    state_path: str | Path = DEFAULT_STATE,
    owners: list[dict] | None = None,
    suppressions: list[dict] | None = None,
    close_resolved: bool = False,
    apply: bool = False,
    backend: TicketBackend | None = None,
    repo: str | None = None,
    label: str = DEFAULT_LABEL,
) -> dict:
    current = load_json(findings_path)
    baseline = load_json(baseline_path) if baseline_path else None
    state = load_state(state_path)
    plan = plan_tickets(
        current,
        baseline=baseline,
        state=state,
        owners=owners or [],
        suppressions=suppressions,
        close_resolved=close_resolved,
    )
    applied = False
    if apply:
        if backend is None:
            backend = GhBackend(repo=repo)
        state = apply_plan(plan, backend, state, label=label)
        save_state(state_path, state)
        applied = True
    return {
        "dry_run": not applied,
        "applied": applied,
        "create": len(plan.create),
        "close": len(plan.close),
        "skip": len(plan.skip),
        "plan": plan_to_dict(plan),
        "state_path": str(state_path),
    }
