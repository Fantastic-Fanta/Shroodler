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


def trend_diff(older: dict, newer: dict) -> dict:
    old_keys = _finding_keys(older)
    new_keys = _finding_keys(newer)
    introduced = sorted(new_keys - old_keys)
    resolved = sorted(old_keys - new_keys)
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
    lines.append(f"unchanged: {trend['unchanged_count']}")
    return "\n".join(lines) + "\n"
