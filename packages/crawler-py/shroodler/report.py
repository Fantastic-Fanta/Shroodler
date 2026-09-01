from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "packages" / "report-generator"))

from reportgen import render  # noqa: E402


def write_report(doc: dict, fmt: str, output: str | None) -> str:
    text = render(doc, fmt)
    if output:
        Path(output).write_text(text, encoding="utf-8")
    return text
