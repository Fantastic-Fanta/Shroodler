#!/usr/bin/env python3
"""Run Python and Go crawlers against the same target and compare structurally."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[2]
PY = ROOT / ".venv" / "bin" / "shroodler"
GO_BIN = ROOT / "packages" / "crawler-go" / "shroodler-go"


def path_set(doc: dict) -> set[str]:
    return {urlparse(p["url"]).path for p in doc.get("pages", [])}


def finding_set(doc: dict) -> set[tuple[str, str, str]]:
    # Includes severity: an engine silently regressing a finding's severity
    # (e.g. a real vulnerability downgraded to "info") would previously pass
    # parity as long as the (id, path) pair still matched, since severity
    # was never compared.
    return {(f["id"], urlparse(f["url"]).path, f["severity"]) for f in doc.get("findings", [])}


def run(bin_path: Path, target: str, dest: Path) -> dict:
    cmd = [str(bin_path), "crawl", target, "--depth", "5", "--output", str(dest)]
    subprocess.run(cmd, check=True, cwd=str(ROOT))
    return json.loads(dest.read_text(encoding="utf-8"))


def compare(py_doc: dict, go_doc: dict) -> list[str]:
    """Compare page paths and finding id+path pairs.

    Timestamps, crawler.version, and stats are ignored — elapsed_ms / request
    counts are not required to match across engines (see docs/DECISIONS.md).
    """
    errs = []
    if path_set(py_doc) != path_set(go_doc):
        errs.append(f"page mismatch py={sorted(path_set(py_doc))} go={sorted(path_set(go_doc))}")
    if finding_set(py_doc) != finding_set(go_doc):
        only_py = finding_set(py_doc) - finding_set(go_doc)
        only_go = finding_set(go_doc) - finding_set(py_doc)
        errs.append(f"finding mismatch only_py={sorted(only_py)} only_go={sorted(only_go)}")
    return errs


def main() -> int:
    targets = sys.argv[1:] or [
        "http://127.0.0.1:8081",
        "http://127.0.0.1:8083",
        "http://127.0.0.1:8084",
    ]
    if not GO_BIN.exists():
        subprocess.run(
            ["go", "build", "-o", str(GO_BIN), "./cmd/shroodler"],
            cwd=str(ROOT / "packages" / "crawler-go"),
            check=True,
        )
    errors: list[str] = []
    for target in targets:
        with tempfile.TemporaryDirectory() as td:
            py_doc = run(PY, target, Path(td) / "py.json")
            go_doc = run(GO_BIN, target, Path(td) / "go.json")
            errors.extend(f"{target}: {e}" for e in compare(py_doc, go_doc))
    if errors:
        for e in errors:
            print(e, file=sys.stderr)
        return 1
    print("parity ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
