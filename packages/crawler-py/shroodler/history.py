"""Local scan history + trend diffing.

`shroodler diff` compares one scan against a static, checked-in baseline
(expected_findings.json) for CI gating. This module is for a different
question: "how has this target's finding set changed over the last N
scans I've run?" -- a lightweight local record of scans, and a diff
between any two of them.

Scans are stored as plain JSON files under a history directory (default
~/.shroodler/history, override with --history-dir or $SHROODLER_HISTORY_DIR).
This is intentionally simple (no database) -- it's a local research aid,
not a multi-user reporting system.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path


def default_history_dir() -> Path:
    env = os.environ.get("SHROODLER_HISTORY_DIR")
    if env:
        return Path(env)
    return Path.home() / ".shroodler" / "history"


def _slugify(text: str) -> str:
    text = re.sub(r"^[a-z]+://", "", text.lower())
    text = re.sub(r"[^a-z0-9]+", "-", text).strip("-")
    return text or "scan"


def _safe_timestamp(doc: dict) -> str:
    ts = doc.get("scan_finished_at") or doc.get("scan_started_at") or ""
    ts = re.sub(r"[^0-9A-Za-z]", "", ts)
    return ts or "0"


def record_scan(doc: dict, history_dir: Path, label: str | None = None) -> Path:
    history_dir.mkdir(parents=True, exist_ok=True)
    name = f"{_safe_timestamp(doc)}_{_slugify(doc.get('target', ''))}"
    if label:
        name += f"_{_slugify(label)}"
    path = history_dir / f"{name}.json"
    suffix = 1
    while path.exists():
        path = history_dir / f"{name}-{suffix}.json"
        suffix += 1
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return path


def list_scans(history_dir: Path, target: str | None = None) -> list[dict]:
    if not history_dir.is_dir():
        return []
    out: list[dict] = []
    for path in sorted(history_dir.glob("*.json")):
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if target and doc.get("target") != target:
            continue
        out.append(
            {
                "id": path.stem,
                "path": str(path),
                "target": doc.get("target", ""),
                "scanned_at": doc.get("scan_finished_at") or doc.get("scan_started_at") or "",
                "findings": len(doc.get("findings", [])),
            }
        )
    return out


def load_scan(history_dir: Path, scan_id_or_path: str) -> dict:
    direct = Path(scan_id_or_path)
    if direct.is_file():
        return json.loads(direct.read_text(encoding="utf-8"))
    candidate = history_dir / f"{scan_id_or_path}.json"
    if candidate.is_file():
        return json.loads(candidate.read_text(encoding="utf-8"))
    raise FileNotFoundError(
        f"{scan_id_or_path!r} is not a file and not a scan id under {history_dir}"
    )


def _finding_keys(doc: dict) -> set[tuple[str, str]]:
    return {(f.get("id", ""), f.get("url", "")) for f in doc.get("findings", [])}


# Lower rank = more severe. Local to this module rather than importing
# report-generator's SEVERITY_RANK: that package is reached via a
# sys.path insert elsewhere in this codebase (see report.py), and a
# 5-entry constant isn't worth adding that indirection to a module that
# otherwise has zero report-generator dependency.
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _severity_by_key(doc: dict) -> dict[tuple[str, str], str]:
    # Last write wins on a duplicate key within one doc (e.g. the same
    # id+url crawled twice some other way) -- irrelevant in practice
    # since crawl output doesn't duplicate keys, but keeps this a total
    # function with no surprise KeyError either way.
    return {
        (f.get("id", ""), f.get("url", "")): f.get("severity", "info")
        for f in doc.get("findings", [])
    }


def trend_diff(older: dict, newer: dict) -> dict:
    old_keys = _finding_keys(older)
    new_keys = _finding_keys(newer)
    introduced = sorted(new_keys - old_keys)
    resolved = sorted(old_keys - new_keys)

    old_severity = _severity_by_key(older)
    new_severity = _severity_by_key(newer)
    severity_increased = []
    for key in sorted(old_keys & new_keys):
        old_sev = old_severity.get(key, "info")
        new_sev = new_severity.get(key, "info")
        # Skip the comparison entirely if either severity string isn't
        # one of the 5 known values, rather than defaulting it to rank 4
        # (least severe): a corrupted/hand-edited history file or a
        # future new severity level this table doesn't know about yet
        # would otherwise make the OLDER severity default to "as if
        # info", so ANY real severity in the newer scan -- even "low",
        # the least severe real value -- would numerically look like an
        # increase. Silently skipping an unrecognized pair is the
        # conservative choice: it can only under-report, never fabricate
        # a regression from bad data.
        if old_sev not in _SEVERITY_RANK or new_sev not in _SEVERITY_RANK:
            continue
        if _SEVERITY_RANK[new_sev] < _SEVERITY_RANK[old_sev]:
            severity_increased.append({"id": key[0], "url": key[1], "from": old_sev, "to": new_sev})

    return {
        "older": {
            "target": older.get("target", ""),
            "scanned_at": older.get("scan_finished_at") or older.get("scan_started_at") or "",
            "findings": len(old_keys),
        },
        "newer": {
            "target": newer.get("target", ""),
            "scanned_at": newer.get("scan_finished_at") or newer.get("scan_started_at") or "",
            "findings": len(new_keys),
        },
        "introduced": [{"id": i, "url": u} for i, u in introduced],
        "resolved": [{"id": i, "url": u} for i, u in resolved],
        # A finding present in BOTH scans (same id+url, so not "introduced")
        # whose severity got worse -- e.g. a header check that used to be
        # "low" now co-occurs with something that bumps it to "medium".
        # diff --gate alone can't see this: it only compares
        # (id, path) presence against a static baseline, which has no
        # severity in it at all, so a same-key severity regression is
        # invisible there. This compares two full scan docs instead
        # (both carry severity already), so no baseline schema change
        # was needed.
        "severity_increased": severity_increased,
        "unchanged_count": len(old_keys & new_keys),
    }


def render_trend_text(trend: dict) -> str:
    lines = [
        f"older: {trend['older']['target']} @ {trend['older']['scanned_at']} "
        f"({trend['older']['findings']} findings)",
        f"newer: {trend['newer']['target']} @ {trend['newer']['scanned_at']} "
        f"({trend['newer']['findings']} findings)",
        "",
    ]
    if trend["introduced"]:
        lines.append(f"introduced ({len(trend['introduced'])}):")
        for f in trend["introduced"]:
            lines.append(f"  + {f['id']} @ {f['url']}")
    else:
        lines.append("introduced: none")
    lines.append("")
    if trend["resolved"]:
        lines.append(f"resolved ({len(trend['resolved'])}):")
        for f in trend["resolved"]:
            lines.append(f"  - {f['id']} @ {f['url']}")
    else:
        lines.append("resolved: none")
    lines.append("")
    if trend["severity_increased"]:
        lines.append(f"severity increased ({len(trend['severity_increased'])}):")
        for f in trend["severity_increased"]:
            lines.append(f"  ! {f['id']} @ {f['url']}: {f['from']} -> {f['to']}")
    else:
        lines.append("severity increased: none")
    lines.append("")
    lines.append(f"unchanged: {trend['unchanged_count']}")
    return "\n".join(lines) + "\n"
