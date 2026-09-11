from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "packages" / "report-generator"))

# findings_from_sarif / merge_findings are re-exported for cli.py; kept despite
# being unused in this module (noqa: F401). E402 is expected everywhere here:
# the reportgen path is inserted above, so these imports cannot sit at the top.
from reportgen import (  # noqa: E402
    findings_from_sarif,  # noqa: F401
    merge_findings,  # noqa: F401
    render,
)
from reportgen import (  # noqa: E402
    render_diff_junit as _diff_junit,
)
from reportgen import (  # noqa: E402
    render_diff_sarif as _diff_sarif,
)


def write_report(doc: dict, fmt: str, output: str | None) -> str:
    if fmt == "pentest":
        from shroodler.pentest_report import render_pentest

        text = render_pentest(doc)
    elif fmt == "pentest-html":
        from shroodler.pentest_report import render_pentest_html

        text = render_pentest_html(doc)
    elif fmt == "submit":
        from shroodler.pentest_report import render_submit

        text = render_submit(doc)
    else:
        text = render(doc, fmt)
    if output:
        Path(output).write_text(text, encoding="utf-8")
    return text


def render_diff_junit(errors: list[str]) -> str:
    return _diff_junit(errors)


def render_diff_sarif(errors: list[str]) -> str:
    return _diff_sarif(errors)
