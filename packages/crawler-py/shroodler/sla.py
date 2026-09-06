"""Per-finding ownership + SLA escalation.

Extends the existing suppression mechanism's `owner`/`expires` fields
(see suppress.py) to findings that are NOT suppressed: every finding
gets resolved to an owner (from an ownership-rules file, same id/url
glob format as `.shroodlerignore`), and its age since it first appeared
in recorded scan history (see history.py) is compared against a
per-severity SLA budget. A finding that's blown its budget gets its
severity escalated by one level for triage purposes (`sla_severity`,
alongside the original `severity`) -- a "medium" nobody has fixed in 90
days deserves to surface as a "high" in a dashboard, the same way a
real incident-management SLA escalates an aging ticket rather than
letting it sit unprioritized forever.

This is deliberately a separate, opt-in post-processing step
(`shroodler sla apply`), not baked into `crawl`/`diff`: it depends on
recorded history existing for the target, which a first-ever scan
won't have.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path

from shroodler.history import default_history_dir, list_scans, load_scan
from shroodler.suppress import glob_match, parse_suppressions, path_of

_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

DEFAULT_SLA_DAYS: dict[str, int] = {
    "critical": 2,
    "high": 7,
    "medium": 30,
    "low": 90,
    "info": 180,
}


def escalate_severity(severity: str) -> str:
    if severity not in _SEVERITY_ORDER:
        return severity
    idx = _SEVERITY_ORDER.index(severity)
    return _SEVERITY_ORDER[min(idx + 1, len(_SEVERITY_ORDER) - 1)]


def load_ownership_rules(path: str | Path | None) -> list[dict]:
    """Same file shape as `.shroodlerignore` (id/url glob rows), reused
    here for a different purpose: instead of suppressing a finding, each
    matching rule's `owner` is attached to it. A rule with no `owner` set
    is simply skipped (nothing to attach)."""
    if path is None:
        return []
    raw = Path(path).read_text(encoding="utf-8")
    return [r for r in parse_suppressions(raw) if r.get("owner")]


def owner_for(finding: dict, rules: list[dict]) -> str:
    fid = finding.get("id", "")
    url = finding.get("url", "")
    path = path_of(url)
    for rule in rules:
        if rule["id"] not in ("*", fid):
            continue
        if glob_match(rule["url"], path) or glob_match(rule["url"], url):
            return rule["owner"]
    return ""


@dataclass
class HistoryFirstSeen:
    """Looks up, and caches, the earliest recorded scan date a given
    (id, url) finding key appeared in -- scans a target's history once
    per instance, not once per finding."""

    history_dir: Path
    target: str | None = None
    _by_key: dict[tuple[str, str], str] | None = None

    def _build_index(self) -> dict[tuple[str, str], str]:
        index: dict[tuple[str, str], str] = {}
        scans = sorted(
            list_scans(self.history_dir, target=self.target),
            key=lambda s: s.get("scanned_at", ""),
        )
        for meta in scans:
            doc = load_scan(self.history_dir, meta["id"])
            scanned_at = (doc.get("scan_finished_at") or doc.get("scan_started_at") or "")[:10]
            for f in doc.get("findings", []):
                key = (f.get("id", ""), f.get("url", ""))
                if key not in index:
                    index[key] = scanned_at
        return index

    def first_seen(self, finding: dict, *, fallback: str) -> str:
        if self._by_key is None:
            self._by_key = self._build_index()
        key = (finding.get("id", ""), finding.get("url", ""))
        return self._by_key.get(key) or fallback


def _age_days(first_seen: str, today: date) -> int | None:
    try:
        seen = date.fromisoformat(first_seen)
    except (ValueError, TypeError):
        return None
    return max(0, (today - seen).days)


def apply_sla(
    doc: dict,
    *,
    history_dir: Path | None = None,
    owners: list[dict] | None = None,
    sla_days: dict[str, int] | None = None,
    today: date | None = None,
) -> dict:
    """Return a copy of `doc` with every finding annotated with
    owner/first_seen/age_days/sla_severity/sla_breached."""
    hist_dir = history_dir or default_history_dir()
    budgets = {**DEFAULT_SLA_DAYS, **(sla_days or {})}
    rules = owners or []
    today = today or datetime.now(timezone.utc).date()
    fallback_seen = today.isoformat()

    finder = HistoryFirstSeen(hist_dir, target=doc.get("target"))
    out_findings = []
    for f in doc.get("findings", []):
        item = dict(f)
        severity = item.get("severity", "info")
        first_seen = finder.first_seen(item, fallback=fallback_seen)
        age = _age_days(first_seen, today) or 0
        budget = budgets.get(severity)
        breached = budget is not None and age > budget
        item["owner"] = owner_for(item, rules) or item.get("owner", "")
        item["first_seen"] = first_seen
        item["age_days"] = age
        item["sla_severity"] = escalate_severity(severity) if breached else severity
        item["sla_breached"] = breached
        out_findings.append(item)

    result = dict(doc)
    result["findings"] = out_findings
    return result
