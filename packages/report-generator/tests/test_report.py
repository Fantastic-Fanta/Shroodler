from __future__ import annotations

import csv
import io
import json
import sys
from pathlib import Path
from xml.etree import ElementTree

from bs4 import BeautifulSoup

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from reportgen import (
    format_evidence,
    render,
    render_csv,
    render_html,
    render_markdown,
    render_sarif,
)

SNAPSHOT = Path(__file__).parent / "snapshots"
EMPTY = {
    "target": "http://127.0.0.1:8081",
    "crawler": {"name": "shroodler-py", "version": "0.1.0", "mode": "static"},
    "pages": [],
    "findings": [],
}
ALL_SEV = {
    "target": "http://127.0.0.1:8081",
    "crawler": {"name": "shroodler-py", "version": "0.1.0", "mode": "static"},
    "pages": [{"url": "http://127.0.0.1:8081/"}],
    "findings": [
        {
            "id": "a",
            "severity": "info",
            "category": "header",
            "url": "http://127.0.0.1:8081/",
            "description": "info finding",
            "evidence": None,
        },
        {
            "id": "b",
            "severity": "critical",
            "category": "secret",
            "url": "http://127.0.0.1:8081/",
            "description": "crit finding",
            "evidence": "AKIA****",
        },
        {
            "id": "c",
            "severity": "low",
            "category": "cookie",
            "url": "http://127.0.0.1:8081/",
            "description": "low finding",
            "evidence": None,
        },
        {
            "id": "d",
            "severity": "high",
            "category": "exposed-file",
            "url": "http://127.0.0.1:8081/",
            "description": "high finding",
            "evidence": None,
        },
        {
            "id": "e",
            "severity": "medium",
            "category": "header",
            "url": "http://127.0.0.1:8081/",
            "description": "med finding",
            "evidence": None,
        },
    ],
}


def test_empty_html_snapshot():
    html = render_html(EMPTY)
    expected = (SNAPSHOT / "empty.html").read_text(encoding="utf-8")
    assert html == expected


def test_all_severities_snapshot():
    html = render_html(ALL_SEV)
    expected = (SNAPSHOT / "all_sev.html").read_text(encoding="utf-8")
    assert html == expected


def test_findings_sorted_by_severity():
    html = render_html(ALL_SEV)
    soup = BeautifulSoup(html, "lxml")
    cells = [td.get_text() for td in soup.select("tbody tr td:first-child")]
    assert cells == ["critical", "high", "medium", "low", "info"]


def test_html_is_parseable():
    soup = BeautifulSoup(render_html(ALL_SEV), "lxml")
    assert soup.find("html") and soup.find("table")


def test_csv_roundtrip():
    text = render_csv(ALL_SEV)
    rows = list(csv.DictReader(io.StringIO(text)))
    assert [r["severity"] for r in rows] == ["critical", "high", "medium", "low", "info"]
    assert len(rows) == 5
    assert render(ALL_SEV, "csv") == text


def test_sarif_and_junit_from_findings():
    sarif = json.loads(render(ALL_SEV, "sarif"))
    assert sarif["version"] == "2.1.0"
    results = sarif["runs"][0]["results"]
    assert len(results) == 5
    levels = {r["ruleId"]: r["level"] for r in results}
    assert levels["b"] == "error"
    assert levels["d"] == "error"
    assert levels["e"] == "warning"
    assert levels["c"] == "note"
    assert levels["a"] == "note"
    by_id = {r["ruleId"]: r for r in results}
    assert by_id["b"]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
        "http://127.0.0.1:8081/"
    )
    empty = json.loads(render_sarif({"findings": []}))
    assert empty["runs"][0]["results"] == []
    assert isinstance(empty["runs"][0]["results"], list)
    xml = render(ALL_SEV, "junit")
    root = ElementTree.fromstring(xml)
    assert root.tag == "testsuite"
    assert int(root.attrib["failures"]) == 5
    empty_junit = render({"findings": [], "crawler": {"name": "shroodler", "version": "0"}}, "junit")
    assert 'failures="0"' in empty_junit


def test_markdown_grouped_by_severity():
    md = render(ALL_SEV, "md")
    assert md == render_markdown(ALL_SEV)
    assert render(ALL_SEV, "markdown") == md
    assert md.startswith("# Shroodler report")
    crit = md.index("## critical")
    high = md.index("## high")
    med = md.index("## medium")
    low = md.index("## low")
    info = md.index("## info")
    assert crit < high < med < low < info
    assert "`b`" in md
    assert "http://127.0.0.1:8081/" in md
    assert "crit finding" in md
    empty = render(EMPTY, "md")
    assert "No findings." in empty
    assert empty.encode("utf-8").decode("utf-8") == empty


def test_markdown_redacts_and_truncates_evidence():
    assert format_evidence("AKIA****") == "AKIA****"
    assert format_evidence("/.git/HEAD") == "/.git/HEAD"
    secret = "AKIAIOSFODNN7EXAMPLE"
    doc = {
        "target": "http://127.0.0.1:8081",
        "crawler": {"name": "shroodler-py", "version": "0.1.0", "mode": "static"},
        "pages": [],
        "findings": [
            {
                "id": "secret",
                "severity": "high",
                "category": "secret",
                "url": "http://127.0.0.1:8081/",
                "description": "key",
                "evidence": secret,
            },
            {
                "id": "verbose",
                "severity": "low",
                "category": "header",
                "url": "http://127.0.0.1:8081/",
                "description": "stack",
                "evidence": ("word " * 40).strip(),
            },
        ],
    }
    md = render_markdown(doc)
    assert secret not in md
    assert "AKIA************MPLE" in md
    verbose_line = next(
        ln for ln in md.splitlines() if ln.startswith("- Evidence:") and "word" in ln
    )
    assert verbose_line.endswith("…`") or "…" in verbose_line
    assert len(verbose_line) < 120
