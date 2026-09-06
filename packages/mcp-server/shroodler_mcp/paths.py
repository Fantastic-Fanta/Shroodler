"""Locate sibling packages that aren't installed (payload-tester,
report-generator) so this server can import them, mirroring the same
lookup pattern `shroodler.cli` already uses for the payload tester."""

from __future__ import annotations

import sys
from pathlib import Path


def _find_dir(*names: str, marker: str, env_var: str) -> Path:
    import os

    env = os.environ.get(env_var)
    if env:
        cand = Path(env)
        if (cand / marker).is_file():
            return cand
        raise FileNotFoundError(f"{env_var} set but {marker} not found in {cand}")
    for parent in Path(__file__).resolve().parents:
        for name in names:
            cand = parent / "packages" / name
            if (cand / marker).is_file():
                return cand
    raise FileNotFoundError(f"could not locate a directory containing {marker}")


def payload_tester_dir() -> Path:
    return _find_dir("payload-tester", marker="tester.py", env_var="SHROODLER_PAYLOAD_DIR")


def report_generator_dir() -> Path:
    return _find_dir(
        "report-generator", marker="remediation.py", env_var="SHROODLER_REPORTGEN_DIR"
    )


def ensure_on_path(path: Path) -> None:
    s = str(path)
    if s not in sys.path:
        sys.path.insert(0, s)
