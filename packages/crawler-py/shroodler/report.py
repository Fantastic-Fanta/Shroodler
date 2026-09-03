from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "packages" / "report-generator"))

from reportgen import render  # noqa: E402
from reportgen import render_diff_junit as _diff_junit  # noqa: E402
from reportgen import render_diff_sarif as _diff_sarif  # noqa: E402


def write_report(doc: dict, fmt: str, output: str | None) -> str:
    text = render(doc, fmt)
    if output:
        Path(output).write_text(text, encoding="utf-8")
    return text


def render_diff_junit(errors: list[str]) -> str:
    return _diff_junit(errors)


def render_diff_sarif(errors: list[str]) -> str:
    return _diff_sarif(errors)
