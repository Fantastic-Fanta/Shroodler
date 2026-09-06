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
    is simply skipped (nothing to attach).

    Unlike a suppression rule (where "id=*, url=*" is an obviously loud,
    dangerous thing to write and review), a mis-scoped catch-all
    ownership rule fails quietly: every finding across the whole scan
    silently gets attributed to one team, which can misdirect
    remediation without anyone noticing. `wildcard_rules()` below lets a
    caller (the CLI) warn about this instead of applying it silently.
    """
    if path is None:
        return []
    raw = Path(path).read_text(encoding="utf-8")
    return [r for r in parse_suppressions(raw) if r.get("owner")]


def wildcard_rules(rules: list[dict]) -> list[dict]:
    """Ownership rules that match everything by id, url, or both -- see
    `load_ownership_rules`'s docstring for why this is worth flagging."""
    return [r for r in rules if r["id"] == "*" or r["url"] in ("*", "")]


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
    per instance, not once per finding.

    Deliberately does NOT fall back to "today" for a key it can't find,
    and does NOT query history at all when `target` is empty/unknown:
    an empty, missing, or freshly-wiped history directory (a fresh CI
    container, a reset volume, `--history-dir` pointed somewhere empty)
    must be distinguishable from "this finding is genuinely new" -- if
    both silently produced first_seen=today, a two-year-old critical
    finding would look brand-new the instant history goes missing,
    permanently and silently defeating SLA escalation. See
    `history_available` below, which callers must check.
    """

    history_dir: Path
    target: str | None = None
    _by_key: dict[tuple[str, str], str] | None = None

    def _build_index(self) -> dict[tuple[str, str], str]:
        if not self.target:
            # Querying history with no target filter would index EVERY
            # target's scans together, letting an unrelated target's
            # (id, url) collision leak a false first_seen date across
            # targets -- safer to report "no history" than a wrong one.
            return {}
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

    @property
    def history_available(self) -> bool:
        """True once at least one prior scan is recorded for this target --
        i.e. "first_seen: today" for a key not in the index is a
        legitimate new-finding answer, not a symptom of missing history."""
        if self._by_key is None:
            self._by_key = self._build_index()
        return bool(self._by_key)

    def first_seen(self, finding: dict) -> str | None:
        """Returns the recorded first-seen date, or None if this exact
        key has never been recorded (whether because history has none of
        this target's scans at all, or because this specific finding is
        genuinely new -- callers distinguish those via
        `history_available`)."""
        if self._by_key is None:
            self._by_key = self._build_index()
        key = (finding.get("id", ""), finding.get("url", ""))
        return self._by_key.get(key)


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
    owner/first_seen/age_days/sla_severity/sla_breached/history_available.

    A finding whose key was never recorded in history is treated as
    genuinely new (first_seen=today, no breach) ONLY when history has
    at least one other recorded scan for this target -- if history has
    NONE (missing/empty/wrong target), first_seen/age_days are left
    None and sla_breached is forced False with history_available=False,
    so a consumer can tell "not enough history to evaluate SLA" apart
    from "evaluated and clean". `shroodler sla apply` prints a warning
    in that case rather than silently reporting a clean result.
    """
    hist_dir = history_dir or default_history_dir()
    budgets = {**DEFAULT_SLA_DAYS, **(sla_days or {})}
    rules = owners or []
    today = today or datetime.now(timezone.utc).date()

    finder = HistoryFirstSeen(hist_dir, target=doc.get("target"))
    history_available = finder.history_available
    out_findings = []
    for f in doc.get("findings", []):
        item = dict(f)
        severity = item.get("severity", "info")
        item["owner"] = owner_for(item, rules) or item.get("owner", "")
        item["history_available"] = history_available

        recorded_first_seen = finder.first_seen(item)
        if recorded_first_seen is not None:
            first_seen = recorded_first_seen
        elif history_available:
            first_seen = today.isoformat()
        else:
            first_seen = None

        if first_seen is None:
            item["first_seen"] = None
            item["age_days"] = None
            item["sla_severity"] = severity
            item["sla_breached"] = False
        else:
            age = _age_days(first_seen, today) or 0
            budget = budgets.get(severity)
            breached = budget is not None and age > budget
            item["first_seen"] = first_seen
            item["age_days"] = age
            item["sla_severity"] = escalate_severity(severity) if breached else severity
            item["sla_breached"] = breached
        out_findings.append(item)

    result = dict(doc)
    result["findings"] = out_findings
    return result
