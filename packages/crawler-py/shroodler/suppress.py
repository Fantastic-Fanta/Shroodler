from __future__ import annotations

import json
import re
from datetime import date, datetime, timedelta, timezone
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
        # Distinguish the KEY being absent (never expires -- the
        # pre-existing behavior for every rule written before this
        # feature existed) from the key being PRESENT but empty/falsy
        # ("expires": "", null, false, 0), which is a malformed value,
        # not an absent one -- review caught that treating both as "never
        # expires" via a truthiness check silently disabled the whole
        # feature for a rule whose expires field got cleared out or
        # misconfigured, which is exactly backwards for a mechanism whose
        # point is to force re-review rather than silently accept risk
        # forever.
        has_expires_key = "expires" in row
        expires_raw = row.get("expires")
        out.append(
            {
                "id": str(row.get("id") or "*"),
                "url": str(row.get("url") or "*"),
                "reason": str(row.get("reason") or ""),
                "owner": str(row.get("owner") or ""),
                "expires": (str(expires_raw) if has_expires_key else None),
            }
        )
    return out


def _parse_expires(value: str | None) -> date | None:
    if value is None:
        return None
    if not isinstance(value, str):
        # A hand-edited YAML file can produce a non-string here (e.g.
        # `expires: 20250101` without quotes parses as an int) --
        # .strip() on that would raise AttributeError instead of failing
        # safe like every other malformed-value case below.
        return date.min
    try:
        return datetime.strptime(value.strip(), "%Y-%m-%d").date()
    except ValueError:
        # An unparseable (or empty/present-but-invalid) expires value
        # fails safe: treat the rule as already-expired (stop
        # suppressing) rather than silently suppressing forever because
        # a date was typo'd or cleared out, and surface it via
        # expired_suppressions() the same way a real expiry would be.
        return date.min


def is_expired(rule: dict, today: date | None = None) -> bool:
    expires = _parse_expires(rule.get("expires"))
    if expires is None:
        return False
    return (today or datetime.now(timezone.utc).date()) > expires


def expires_malformed(rule: dict) -> bool:
    """True when `expires` is present but isn't a valid YYYY-MM-DD date
    (including present-but-empty) -- distinguished from a rule that
    genuinely aged out, so a warning can tell a human "you typo'd this"
    apart from "this expired on schedule"."""
    raw = rule.get("expires")
    if raw is None:
        return False
    if not isinstance(raw, str):
        return True
    return _parse_expires(raw) == date.min and raw.strip() != date.min.isoformat()


def expiring_within(rules: list[dict], days: int, today: date | None = None) -> list[dict]:
    """Rules with a real, non-expired `expires` date that falls within the
    next `days` days -- the "scheduled suppression-expiry PR" mechanism:
    a warning in CI logs (see expired_suppressions) is easy to scroll
    past, but a rule that's ABOUT to expire, listed here, is exactly the
    input a scheduled job needs to open a PR nudging someone to either
    extend-with-justification or remove it, before it silently starts
    failing `diff --gate` with no notice."""
    now = today or datetime.now(timezone.utc).date()
    horizon = now + timedelta(days=days)
    out = []
    for rule in rules:
        expires = _parse_expires(rule.get("expires"))
        if expires is None or expires == date.min:
            continue  # never expires, or malformed (already surfaced elsewhere)
        if now <= expires <= horizon:
            out.append(rule)
    return out


def _md_code_escape(value: str) -> str:
    """Make an arbitrary string safe to place inside a single backtick
    code span: strip characters that could close the span early or
    inject Markdown/line structure into a PR body a CI job posts
    unattended (backticks, newlines/carriage-returns, and pipes, which
    could otherwise break out into surrounding table/list structure)."""
    return str(value).replace("`", "'").replace("\n", " ").replace("\r", " ").replace("|", "/")


def render_expiring_pr_body(rules: list[dict], days: int) -> str:
    """Markdown body a scheduled CI job can hand straight to `gh pr create
    --body` (or equivalent) to open a PR nudging someone to
    extend-with-justification or remove each rule before it expires --
    this module only generates the content; actually opening the PR
    (running `gh`, pushing a branch) is CI's job, not this library's, so
    it stays free of any network/credential concerns.

    Suppression files are normally PR-reviewed, so a hostile id/url/
    owner/reason getting in here at all is unlikely -- fields are still
    escaped and placed inside Markdown code spans as defense in depth,
    since this text is posted into a PR body unattended. ALL FOUR
    interpolated fields (id, url, owner, reason) are wrapped in code
    spans, not just id/url -- code spans suppress link/emphasis/etc.
    Markdown parsing entirely, which plain-prose interpolation (the
    earlier, incomplete version of this fix) would not have caught for
    a `reason` like "legit [click here](http://evil.example/)".
    """
    if not rules:
        return f"No suppression rules expire within the next {days} day(s)."
    lines = [
        f"The following suppression rule(s) expire within {days} day(s). "
        "Extend with a justification, or remove them and let the finding "
        "reappear in `diff --gate`.",
        "",
    ]
    for rule in rules:
        rid = _md_code_escape(rule["id"])
        url = _md_code_escape(rule["url"])
        expires = _md_code_escape(rule["expires"])
        owner = _md_code_escape(rule["owner"]) or "(unset)"
        reason = _md_code_escape(rule["reason"]) or "(none)"
        lines.append(
            f"- `id={rid}` `url={url}` expires **{expires}** "
            f"(owner: `{owner}`; reason: `{reason}`)"
        )
    return "\n".join(lines) + "\n"


def expired_suppressions(rules: list[dict], today: date | None = None) -> list[dict]:
    """Rules with a real `expires` date that has passed (or an
    unparseable one, which fails safe to "expired") -- surfaced so
    `diff --gate` (and every other command that loads suppressions) can
    warn about them instead of a suppression silently aging out of
    relevance, or silently stopping enforcement on a typo'd date, with no
    one noticing either way."""
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
