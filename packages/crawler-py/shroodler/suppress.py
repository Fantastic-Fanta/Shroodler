from __future__ import annotations

import json
import re
from datetime import date, datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import yaml


def path_of(url: str) -> str:
    p = urlparse(url)
    path = p.path or "/"
    return path


def glob_match(pattern: str, value: str) -> bool:
    if not pattern or pattern == "*":
        return True
    escaped = re.escape(pattern)
    regex = "^" + escaped.replace(r"\*", ".*").replace(r"\?", ".") + "$"
    return re.search(regex, value) is not None


def load_suppressions(path: str | Path | None = None) -> list[dict]:
    if path is None:
        candidate = Path(".shroodlerignore")
        if not candidate.is_file():
            return []
        path = candidate
    raw = Path(path).read_text(encoding="utf-8")
    return parse_suppressions(raw)


def parse_suppressions(raw: str) -> list[dict]:
    text = raw.strip()
    if not text:
        return []
    if text.startswith("[") or text.startswith("{"):
        data = json.loads(text)
    else:
        data = yaml.safe_load(text) or {}
    if isinstance(data, list):
        rows = data
    else:
        rows = data.get("suppressions") or []
    out: list[dict] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        expires_raw = row.get("expires")
        out.append(
            {
                "id": str(row.get("id") or "*"),
                "url": str(row.get("url") or "*"),
                "reason": str(row.get("reason") or ""),
                "owner": str(row.get("owner") or ""),
                # None means "never expires" -- the pre-existing,
                # unchanged behavior for a rule that doesn't set this
                # field at all.
                "expires": str(expires_raw) if expires_raw else None,
            }
        )
    return out


def _parse_expires(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        # An unparseable expires value fails safe: treat the rule as
        # already-expired (stop suppressing) rather than silently
        # suppressing forever because a date was typo'd, and surface it
        # via expired_suppressions() the same way a real expiry would be.
        return date.min


def is_expired(rule: dict, today: date | None = None) -> bool:
    expires = _parse_expires(rule.get("expires"))
    if expires is None:
        return False
    return (today or datetime.now(timezone.utc).date()) > expires


def expired_suppressions(rules: list[dict], today: date | None = None) -> list[dict]:
    """Rules with a real `expires` date that has passed -- surfaced so
    `diff --gate` can warn about them instead of a suppression silently
    aging out of relevance (or, per is_expired's fail-safe, silently
    stopping enforcement of a suppression on a typo'd date) with no one
    noticing either way."""
    return [r for r in rules if is_expired(r, today)]


def finding_suppressed(finding: dict, rules: list[dict], today: date | None = None) -> dict | None:
    fid = finding.get("id", "")
    url = finding.get("url", "")
    path = path_of(url)
    for rule in rules:
        if is_expired(rule, today):
            continue
        if rule["id"] not in ("*", fid):
            continue
        if glob_match(rule["url"], path) or glob_match(rule["url"], url):
            return rule
    return None


def filter_findings(
    findings: list[dict], rules: list[dict], today: date | None = None
) -> list[dict]:
    if not rules:
        return list(findings)
    return [f for f in findings if finding_suppressed(f, rules, today) is None]
