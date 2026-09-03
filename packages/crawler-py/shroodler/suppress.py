from __future__ import annotations

import json
import re
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
        out.append(
            {
                "id": str(row.get("id") or "*"),
                "url": str(row.get("url") or "*"),
                "reason": str(row.get("reason") or ""),
            }
        )
    return out


def finding_suppressed(finding: dict, rules: list[dict]) -> dict | None:
    fid = finding.get("id", "")
    url = finding.get("url", "")
    path = path_of(url)
    for rule in rules:
        if rule["id"] not in ("*", fid):
            continue
        if glob_match(rule["url"], path) or glob_match(rule["url"], url):
            return rule
    return None


def filter_findings(findings: list[dict], rules: list[dict]) -> list[dict]:
    if not rules:
        return list(findings)
    return [f for f in findings if finding_suppressed(f, rules) is None]
