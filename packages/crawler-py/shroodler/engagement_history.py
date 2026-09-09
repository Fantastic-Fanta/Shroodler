"""Program memory across engagements: endpoint diffs and operator suppressions."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from shroodler.models import Finding
from shroodler.program import ProgramState


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _param_names(meta: Any) -> set[str]:
    if not isinstance(meta, dict):
        return set()
    names: set[str] = set()
    for item in meta.get("params") or []:
        if isinstance(item, str):
            name = item.strip()
            if name:
                names.add(name)
            continue
        if isinstance(item, dict):
            name = str(item.get("name") or item.get("key") or "").strip()
            if name:
                names.add(name)
    return names


@dataclass
class EngagementDiff:
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    param_changed: list[dict[str, Any]] = field(default_factory=list)


def diff_endpoints(old: dict, new: dict) -> EngagementDiff:
    """Return added, removed, and param-changed endpoints since last run."""
    old_map = old or {}
    new_map = new or {}
    old_urls = set(old_map)
    new_urls = set(new_map)
    changed: list[dict[str, Any]] = []
    for url in sorted(old_urls & new_urls):
        before = _param_names(old_map.get(url))
        after = _param_names(new_map.get(url))
        if before != after:
            changed.append(
                {
                    "url": url,
                    "old": sorted(before),
                    "new": sorted(after),
                }
            )
    return EngagementDiff(
        added=sorted(new_urls - old_urls),
        removed=sorted(old_urls - new_urls),
        param_changed=changed,
    )


def record_suppression(state: ProgramState, finding_id: str, url: str, reason: str) -> None:
    """Mark a finding as suppressed so it is never re-emitted."""
    fid = str(finding_id or "")
    target = str(url or "*")
    why = str(reason or "")
    rows = list(state.suppressed_findings or [])
    for row in rows:
        if not isinstance(row, dict):
            continue
        if str(row.get("id") or "") == fid and str(row.get("url") or "*") == target:
            row["reason"] = why
            row["suppressed_at"] = str(row.get("suppressed_at") or _now())
            state.suppressed_findings = rows
            return
    rows.append(
        {
            "id": fid,
            "url": target,
            "reason": why,
            "suppressed_at": _now(),
        }
    )
    state.suppressed_findings = rows


def is_suppressed(state: ProgramState, finding_id: str, url: str) -> bool:
    """True if this finding+url combo was suppressed by the operator."""
    fid = str(finding_id or "")
    target = str(url or "")
    for row in state.suppressed_findings or []:
        if not isinstance(row, dict):
            continue
        if str(row.get("id") or "") != fid:
            continue
        rule_url = str(row.get("url") or "*")
        if rule_url == "*" or rule_url == target:
            return True
    return False


def surface_changes(diff: EngagementDiff) -> list[Finding]:
    """Emit findings for new/removed/changed endpoints."""
    out: list[Finding] = []
    for url in diff.added:
        out.append(
            Finding(
                id="new-endpoint",
                severity="info",
                category="scan-note",
                url=url,
                description=f"New endpoint discovered since the previous engagement: {url}",
                evidence="added since previous snapshot",
                confidence="heuristic",
            )
        )
    for url in diff.removed:
        out.append(
            Finding(
                id="removed-endpoint",
                severity="info",
                category="scan-note",
                url=url,
                description=f"Endpoint present in the previous engagement is gone: {url}",
                evidence="removed since previous snapshot",
                confidence="heuristic",
            )
        )
    for row in diff.param_changed:
        url = str(row.get("url") or "")
        old = ",".join(row.get("old") or [])
        new = ",".join(row.get("new") or [])
        out.append(
            Finding(
                id="param-changed",
                severity="info",
                category="scan-note",
                url=url,
                description=(f"Parameter set changed on {url}: [{old}] -> [{new}]"),
                evidence=f"old={old} new={new}",
                confidence="heuristic",
            )
        )
    return out


def format_run_history(state: ProgramState) -> str:
    """Table: date, iterations, confirmed, new endpoints, delta from previous run."""
    rows = list(state.run_history or [])
    if not rows:
        return "No engagement runs recorded.\n"
    headers = ("DATE", "ITER", "CONFIRMED", "NEW ENDPOINTS", "DELTA")
    table: list[list[str]] = []
    prev_confirmed: int | None = None
    prev_new: int | None = None
    for row in rows:
        if not isinstance(row, dict):
            continue
        confirmed = int(row.get("confirmed") or 0)
        new_eps = int(row.get("new_endpoints") or 0)
        if prev_confirmed is None:
            delta = "-"
        else:
            d_conf = confirmed - prev_confirmed
            d_eps = new_eps - prev_new if prev_new is not None else 0
            delta = f"confirmed {d_conf:+d}, new_endpoints {d_eps:+d}"
        table.append(
            [
                str(row.get("started_at") or ""),
                str(int(row.get("iterations") or 0)),
                str(confirmed),
                str(new_eps),
                delta,
            ]
        )
        prev_confirmed = confirmed
        prev_new = new_eps
    widths = [len(h) for h in headers]
    for row in table:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    lines = ["  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))]
    lines.append("  ".join("-" * w for w in widths))
    for row in table:
        lines.append("  ".join(row[i].ljust(widths[i]) for i in range(len(headers))))
    return "\n".join(lines) + "\n"


def format_endpoint_diff(diff: EngagementDiff) -> str:
    lines = [
        f"added: {len(diff.added)}",
        f"removed: {len(diff.removed)}",
        f"param-changed: {len(diff.param_changed)}",
        "",
    ]
    if diff.added:
        lines.append("added:")
        for url in diff.added:
            lines.append(f"  + {url}")
        lines.append("")
    if diff.removed:
        lines.append("removed:")
        for url in diff.removed:
            lines.append(f"  - {url}")
        lines.append("")
    if diff.param_changed:
        lines.append("param-changed:")
        for row in diff.param_changed:
            url = row.get("url") or ""
            old = ",".join(row.get("old") or [])
            new = ",".join(row.get("new") or [])
            lines.append(f"  ~ {url} [{old}] -> [{new}]")
        lines.append("")
    return "\n".join(lines)
