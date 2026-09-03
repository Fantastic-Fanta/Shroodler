from __future__ import annotations

import csv
import io
from pathlib import Path

from bs4 import BeautifulSoup

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from reportgen import render, render_csv, render_html

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
