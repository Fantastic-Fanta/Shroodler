from __future__ import annotations

import math
import re
from functools import lru_cache
from pathlib import Path

import yaml

from shroodler.models import Finding

SEVERITY = {
    "info": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


def rules_dir() -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "packages" / "secret-patterns" / "rules"
        if candidate.is_dir():
            return candidate
        # installed layout: repo/packages/secret-patterns/rules
        alt = parent / "secret-patterns" / "rules"
        if alt.is_dir():
            return alt
    raise FileNotFoundError("secret-patterns/rules not found")


@lru_cache(maxsize=1)
def load_rules() -> list[dict]:
    rules: list[dict] = []
    for path in sorted(rules_dir().glob("*.yaml")):
        loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        rules.extend(loaded)
    return rules


def redact(value: str) -> str:
    if len(value) <= 8:
        return value[0:2] + "****"
    return value[:4] + "************" + value[-4:]


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


_ENTROPY_TOKEN = re.compile(r"\b[A-Za-z0-9_\-/+=]{32,64}\b")


def _entropy_hits(text: str) -> list[str]:
    hits = []
    for m in _ENTROPY_TOKEN.finditer(text):
        token = m.group(0)
        if token.startswith("eyJ"):
            continue
        if token.startswith("AKIA"):
            continue
        if _shannon(token) >= 4.2 and len(set(token)) >= 16:
            hits.append(token)
    return hits


def scan_text(text: str, url: str) -> list[Finding]:
    if not text:
        return []
    findings: list[Finding] = []
    for rule in load_rules():
        rid = rule["id"]
        pattern = rule["pattern"]
        severity = SEVERITY.get(str(rule.get("severity", "medium")), "medium")
        desc = rule.get("description", rid)
        if pattern == "__ENTROPY__":
            for token in _entropy_hits(text):
                findings.append(
                    Finding(
                        id=rid,
                        severity=severity,  # type: ignore[arg-type]
                        category="secret",
                        url=url,
                        description=desc,
                        evidence=redact(token),
                    )
                )
            continue
        try:
            regex = re.compile(pattern)
        except re.error:
            continue
        for m in regex.finditer(text):
            raw = m.group(0)
            findings.append(
                Finding(
                    id=rid,
                    severity=severity,  # type: ignore[arg-type]
                    category="secret",
                    url=url,
                    description=desc,
                    evidence=redact(raw),
                )
            )
    return findings
