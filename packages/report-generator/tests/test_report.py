from __future__ import annotations

import csv
import io
import json
import sys
from pathlib import Path
from xml.etree import ElementTree

from bs4 import BeautifulSoup

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from remediation import remediation_for
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
    cells = [td.get_text() for td in soup.select("#detail-findings tbody tr td:first-child")]
    assert cells == ["critical", "high", "medium", "low", "info"]


def test_html_is_parseable():
    soup = BeautifulSoup(render_html(ALL_SEV), "lxml")
    assert soup.find("html") and soup.find("table")


def test_html_executive_summary_scores_by_distinct_finding_not_raw_instances():
    # A single missing-CSP finding repeated across 5 pages must score as
    # ONE medium-severity distinct issue (weight 4), not five.
    doc = {
        "target": "http://127.0.0.1:8081",
        "crawler": {"name": "shroodler-py", "version": "0.1.0", "mode": "static"},
        "pages": [{"url": f"http://127.0.0.1:8081/p{i}"} for i in range(5)],
        "findings": [
            {
                "id": "missing-csp",
                "severity": "medium",
                "category": "header",
                "url": f"http://127.0.0.1:8081/p{i}",
                "description": "Missing Content-Security-Policy header",
                "evidence": None,
            }
            for i in range(5)
        ],
    }
    html = render_html(doc)
    soup = BeautifulSoup(html, "lxml")
    grade = soup.select_one(".risk-grade")
    assert grade is not None
    # Score alone (4) would band as B, but any medium present is floored
    # to at least C -- see risk_score.py's severity-floor rationale.
    assert grade.get_text().strip() == "C"
    assert "1 medium" in soup.select_one(".risk-counts").get_text()


def test_html_executive_summary_grade_f_for_multiple_criticals():
    doc = dict(ALL_SEV, findings=ALL_SEV["findings"] + [
        {
            "id": "another-critical",
            "severity": "critical",
            "category": "secret",
            "url": "http://127.0.0.1:8081/",
            "description": "another crit",
            "evidence": None,
        }
    ])
    html = render_html(doc)
    soup = BeautifulSoup(html, "lxml")
    grade_text = soup.select_one(".risk-grade").get_text().strip()
    # Any critical present floors the grade to F outright, regardless of
    # the numeric score -- pinned exactly, not a membership check.
    assert grade_text == "F"


def test_empty_scan_gets_grade_a_executive_summary():
    html = render_html(EMPTY)
    soup = BeautifulSoup(html, "lxml")
    assert soup.select_one(".risk-grade").get_text().strip() == "A"


def test_html_groups_repeated_findings_into_a_summary():
    doc = {
        "target": "http://127.0.0.1:8081",
        "crawler": {"name": "shroodler-py", "version": "0.1.0", "mode": "static"},
        "pages": [{"url": f"http://127.0.0.1:8081/p{i}"} for i in range(5)],
        "findings": [
            {
                "id": "missing-csp",
                "severity": "medium",
                "category": "header",
                "url": f"http://127.0.0.1:8081/p{i}",
                "description": "Missing Content-Security-Policy header",
                "evidence": None,
            }
            for i in range(5)
        ],
    }
    html = render_html(doc)
    soup = BeautifulSoup(html, "lxml")
    detail_rows = soup.select("#detail-findings tbody tr")
    assert len(detail_rows) == 5  # every finding is still present in detail
    summary_rows = soup.select("table:not(#detail-findings) tbody tr")
    assert len(summary_rows) == 1  # but rolled up to one row in the summary
    assert "5" in summary_rows[0].get_text()


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
    # artifactLocation.uri must be relative (no scheme) so GitHub code-scanning's
    # SARIF ingestion accepts it; the real live URL is preserved separately.
    location = by_id["b"]["locations"][0]["physicalLocation"]["artifactLocation"]
    assert location["uri"] == "127.0.0.1_8081/"
    assert location["uriBaseId"] == "SCANTARGET"
    assert by_id["b"]["properties"]["target_url"] == "http://127.0.0.1:8081/"
    run = sarif["runs"][0]
    assert run["originalUriBaseIds"]["SCANTARGET"]["uri"].startswith("http")
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


def test_markdown_includes_risk_score():
    md = render(ALL_SEV, "md")
    assert "**Grade:" in md
    empty_md = render(EMPTY, "md")
    assert "**Grade: A** (0 risk points)" in empty_md


def test_markdown_partial_coverage_caveat():
    doc = dict(EMPTY, findings=[
        {
            "id": "waf-challenge-sitewide",
            "severity": "info",
            "category": "waf-challenge",
            "url": "http://127.0.0.1:8081/",
            "description": "most of the scan was challenged",
            "evidence": None,
        }
    ])
    md = render(doc, "md")
    assert "could not fully test the target" in md


def test_known_finding_id_gets_specific_remediation():
    assert "Secure" in remediation_for("insecure-cookie", "cookie")
    assert remediation_for("insecure-cookie", "cookie") != remediation_for("cookie", "cookie")


def test_unknown_id_falls_back_to_category_then_default():
    assert "credential" in remediation_for("some-brand-new-secret-id", "secret").lower()
    assert remediation_for("totally-unknown-id", "totally-unknown-category")


def test_missing_rate_limit_id_matches_real_finding_id():
    # Was previously keyed as the non-existent "rate-limit-missing",
    # silently falling back to the generic auth-category text.
    assert "rate limiting" in remediation_for("missing-rate-limit", "auth").lower()


def test_authz_finding_ids_have_specific_remediation():
    assert "authz-still-accessible" not in remediation_for("authz-still-accessible", "auth")
    assert remediation_for("authz-still-accessible", "auth") != remediation_for("x", "auth")
    assert remediation_for("authz-broken-access-control", "auth") != remediation_for("x", "auth")


def test_html_summary_includes_remediation_column():
    html = render_html(ALL_SEV)
    soup = BeautifulSoup(html, "lxml")
    header_cells = [th.get_text() for th in soup.select("table")[0].select("thead th")]
    assert "Remediation" in header_cells


def test_markdown_includes_remediation_line():
    md = render(ALL_SEV, "md")
    assert "- Remediation:" in md


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


def test_render_markdown_escapes_hostile_html_in_free_text_fields():
    # Regression test for a real bug the adversarial self-scan found:
    # description/url/evidence are sourced from the scanned TARGET's own
    # responses, and markdown reports are commonly rendered as rich text
    # downstream (GitHub, chat clients) where CommonMark passes raw
    # inline HTML straight through -- a hostile payload must not survive
    # verbatim into the output.
    payload = "<script>alert('xss')</script>"
    doc = {
        "target": "http://x",
        "findings": [
            {
                "id": "missing-hsts",
                "severity": "medium",
                "category": "header",
                "url": f"http://x/{payload}",
                "description": f"reflected: {payload}",
                "evidence": payload,
            }
        ],
    }
    md = render_markdown(doc)
    assert payload not in md
    assert "&lt;script&gt;" in md


def test_render_markdown_neutralizes_backtick_code_span_breakout():
    # Regression test: a backtick in url/evidence/id must not be able to
    # prematurely close the single-backtick code span it's placed in --
    # html.escape() alone doesn't touch backticks, so this needed a
    # separate fix (_md_inline_code_safe) on top of the HTML-escaping.
    breakout = "http://x/a`) malicious markdown **injected** [link](http://evil)"
    doc = {
        "target": "http://x",
        "findings": [
            {
                "id": "missing-hsts",
                "severity": "medium",
                "category": "header",
                "url": breakout,
                "description": "d",
                "evidence": "e`vil",
            }
        ],
    }
    md = render_markdown(doc)
    # The URL line's code span must still be intact -- a backtick from
    # the payload should never appear as a literal, unescaped backtick
    # inside the rendered markdown.
    url_line = next(ln for ln in md.splitlines() if ln.startswith("- URL:"))
    assert url_line.count("`") == 2  # opening + closing span only
    evidence_line = next(ln for ln in md.splitlines() if ln.startswith("- Evidence:"))
    assert evidence_line.count("`") == 2


def test_render_csv_neutralizes_formula_injection():
    # Regression test for a real bug the adversarial self-scan found:
    # a cell value starting with =, +, -, or @ is interpreted as a
    # formula by Excel/Sheets -- content sourced from the scanned
    # target must be neutralized (OWASP CSV Injection guidance: a
    # leading apostrophe) before being written.
    doc = {
        "target": "http://x",
        "findings": [
            {
                "id": "missing-hsts",
                "severity": "medium",
                "category": "header",
                "url": "http://x/a",
                "description": "=cmd|'/c calc'!A1",
                "evidence": "+SUM(1+1)",
            }
        ],
    }
    text = render_csv(doc)
    rows = list(csv.DictReader(io.StringIO(text)))
    assert rows[0]["description"] == "'=cmd|'/c calc'!A1"
    assert rows[0]["evidence"] == "'+SUM(1+1)"
