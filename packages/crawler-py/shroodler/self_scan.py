"""Adversarial self-scan: crawl the tool's OWN generated report output as
a fuzz target, catching stored-XSS-via-echoed-payload-in-report -- a
real, semi-famous scanner bug class (a report that faithfully displays
what a hostile target sent back can itself become an XSS delivery
vector for whoever opens the report). Cheap to build, genuinely novel as
dogfooding: this feeds synthetic findings whose free-text fields (url,
evidence, description) carry classic injection shapes through every
report renderer this tool ships, then inspects the RENDERED OUTPUT BYTES
for evidence of a real defect.

"Self-scan" names the idea (turn the tool's own artifact into the fuzz
target), not a literal reuse of the crawler machinery -- report
renderers here are pure functions from a dict to a string, so there's
nothing to crawl in the traditional sense.

Each output format has a DIFFERENT correctness contract, so this checks
a different thing per format rather than applying one "is HTML escaped"
rule everywhere (an earlier version of this module did that and flagged
CSV/SARIF as "unescaped HTML" -- a category error: neither format
promises HTML-escaping, and firing on every run for something that was
never a bug is worse than not checking at all):

- html, markdown: HTML/JS-injection payloads must not survive verbatim
  -- both are commonly rendered as rich text by *something* downstream
  (a browser; a Markdown viewer, GitHub PR comment, or chat client for
  markdown), so raw <script>/onerror=/onload= content surviving is a
  real stored-XSS risk even though this tool doesn't render either
  itself.
- sarif (JSON), junit (XML): a hostile field must not break the
  format's own structural well-formedness. This is genuinely a
  correctness bug regardless of any browser: a SARIF/JUnit consumer
  (GitHub code scanning, a CI test-results UI) that can't even parse
  the file is a real defect, and unescaped `<`/`&` in an XML text node
  is exactly the kind of thing that would cause it.
- csv: the well-known "CSV injection" class -- a cell value starting
  with `=`, `+`, `-`, or `@` is interpreted as a formula by Excel/Sheets
  when the file is opened, potentially executing attacker-controlled
  content. A correct renderer neutralizes this (e.g. a leading
  apostrophe/quote); this checks that it does.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET

_HTML_PAYLOADS = [
    "<script>alert('shroodler-self-scan-xss')</script>",
    '"><img src=x onerror=alert(1)>',
    "'><svg onload=alert(1)>",
]

_CSV_FORMULA_PAYLOADS = [
    "=cmd|'/c calc'!A1",
    "+SUM(1+1)",
    "-2+3",
    "@SUM(1+1)",
    # A comma (or embedded quote) forces Python's csv module to wrap the
    # WHOLE field in double quotes -- e.g. `=1+1,cmd|calc` serializes as
    # `"=1+1,cmd|calc"`, so the character immediately following the
    # preceding delimiter is `"`, not `=`. A detector that string-matches
    # `,{payload}` against the raw serialized line (rather than parsing
    # the CSV back into cells) would silently miss this -- included here
    # specifically to keep that check honest.
    "=1+1,cmd|'/c calc'!A1",
    # A newline forces the same quoting requirement as a comma. A naive
    # renderer that writes this unquoted would split the file into an
    # extra physical line -- caught here via the row-count check
    # (exactly 1 row expected), not the exact-cell-value check, since a
    # split payload's fragments individually never equal the whole
    # payload string.
    "=cmd|calc\nEXTRA_INJECTED_LINE",
]


def _adversarial_doc(payload: str) -> dict:
    return {
        "target": "http://self-scan.invalid",
        "scan_started_at": "2020-01-01T00:00:00Z",
        "scan_finished_at": "2020-01-01T00:00:01Z",
        "crawler": {"name": "shroodler", "version": "0.0.0", "mode": "static"},
        "pages": [],
        "js_endpoints": [],
        "findings": [
            {
                "id": "missing-hsts",
                "severity": "medium",
                "category": "header",
                "url": f"http://self-scan.invalid/{payload}",
                "description": f"Reflected value from target: {payload}",
                "evidence": payload,
            }
        ],
    }


def _adversarial_doc_crawler_field(payload: str) -> dict:
    """Same shape as `_adversarial_doc`, but the payload goes into
    `crawler.name` instead of a finding field -- this isn't reflected
    from the scanned target by either crawler engine today, but a
    renderer's escaping discipline shouldn't silently depend on that
    staying true forever, and a prior version of this module's own
    defensive escaping for crawler metadata regressed without any test
    catching it."""
    doc = _adversarial_doc("harmless")
    doc["crawler"]["name"] = payload
    return doc


def _crash_finding(fmt: str, payload: str, exc: Exception) -> dict:
    return {
        "id": "self-scan-renderer-crash",
        "severity": "high",
        "category": "payload",
        "url": f"report-format://{fmt}",
        "description": (
            f"The {fmt} report renderer raised an exception when a finding's "
            f"free-text field contained {payload!r}: {exc}"
        ),
        "evidence": payload,
    }


def _unescaped_html_finding(fmt: str, payload: str, *, field: str) -> dict:
    return {
        "id": "self-scan-unescaped-html",
        "severity": "critical",
        "category": "payload",
        "url": f"report-format://{fmt}",
        "description": (
            f"The {fmt} report renderer echoed a hostile {field} field "
            f"({payload!r}) into its output UNESCAPED -- since {fmt} output "
            "is commonly rendered as rich text downstream, this is a "
            "stored-XSS vector for content sourced from the scanned "
            "target's own responses (or, for crawler metadata, defense in "
            "depth against that assumption ever changing)."
        ),
        "evidence": payload,
    }


def _check_html_escaping(fmt: str, render_fn) -> list[dict]:
    findings = []
    for payload in _HTML_PAYLOADS:
        try:
            rendered = render_fn(_adversarial_doc(payload), fmt)
        except Exception as exc:  # noqa: BLE001 - a crash on hostile input is itself a finding
            findings.append(_crash_finding(fmt, payload, exc))
            continue
        if payload in rendered:
            findings.append(_unescaped_html_finding(fmt, payload, field="finding"))

        # Also check crawler metadata (name/version/mode) -- not
        # currently reflected from the scanned target by either crawler
        # engine, but a renderer's escaping discipline for it shouldn't
        # silently depend on that staying true forever.
        try:
            rendered_meta = render_fn(_adversarial_doc_crawler_field(payload), fmt)
        except Exception as exc:  # noqa: BLE001
            findings.append(_crash_finding(fmt, payload, exc))
            continue
        if payload in rendered_meta:
            findings.append(_unescaped_html_finding(fmt, payload, field="crawler metadata"))
    return findings


def _check_well_formed(fmt: str, render_fn, parse_fn) -> list[dict]:
    findings = []
    for payload in _HTML_PAYLOADS:
        try:
            rendered = render_fn(_adversarial_doc(payload), fmt)
        except Exception as exc:  # noqa: BLE001
            findings.append(_crash_finding(fmt, payload, exc))
            continue
        try:
            parse_fn(rendered)
        except Exception as exc:  # noqa: BLE001 - malformed output from hostile input
            findings.append(
                {
                    "id": "self-scan-malformed-output",
                    "severity": "high",
                    "category": "payload",
                    "url": f"report-format://{fmt}",
                    "description": (
                        f"A hostile finding field ({payload!r}) broke the {fmt} "
                        f"renderer's own output structure ({exc}) -- a consumer "
                        "parsing this file (a CI test-results UI, GitHub code "
                        "scanning) would fail on it or worse."
                    ),
                    "evidence": payload,
                }
            )
    return findings


def _check_csv_formula_injection(render_fn) -> list[dict]:
    import csv
    import io

    findings = []
    for payload in _CSV_FORMULA_PAYLOADS:
        try:
            rendered = render_fn(_adversarial_doc(payload), "csv")
        except Exception as exc:  # noqa: BLE001
            findings.append(_crash_finding("csv", payload, exc))
            continue
        # Parse the CSV back into cells rather than string-matching the
        # raw serialized text: Python's csv module wraps a field in
        # double quotes whenever it contains the delimiter, a quote
        # char, or a newline (e.g. a payload containing a comma
        # serializes as `"=1+1,cmd|calc"`), which shifts what character
        # immediately follows a preceding comma and would defeat a
        # naive `f",{payload}" in rendered` substring check -- that
        # exact gap is why _CSV_FORMULA_PAYLOADS includes a comma-
        # bearing payload.
        try:
            rows = list(csv.DictReader(io.StringIO(rendered)))
        except csv.Error as exc:
            findings.append(_crash_finding("csv", payload, exc))
            continue
        # csv.DictReader is lenient by design -- it raises on almost
        # nothing, so a renderer that silently dropped the row, or (for
        # a newline-bearing payload) split it across multiple rows,
        # would otherwise parse "successfully" into zero or the wrong
        # number of rows, with `vulnerable` staying False by omission
        # rather than by an actual safety check. This doc always
        # produces exactly one finding, so exactly one row back is the
        # only structurally-sound outcome; anything else is a defect in
        # its own right, distinct from (but as serious as) an
        # unneutralized formula trigger.
        if len(rows) != 1:
            findings.append(
                {
                    "id": "self-scan-malformed-output",
                    "severity": "high",
                    "category": "payload",
                    "url": "report-format://csv",
                    "description": (
                        f"The csv report renderer produced {len(rows)} row(s) instead "
                        f"of 1 for a single finding whose field contained {payload!r} -- "
                        "the row was likely dropped, or a payload containing a comma/"
                        "newline/quote was written without the quoting CSV requires, "
                        "silently corrupting the file's structure."
                    ),
                    "evidence": payload,
                }
            )
            continue
        vulnerable = any(
            isinstance(cell, str) and cell == payload
            for cell in rows[0].values()
        )
        if vulnerable:
            findings.append(
                {
                    "id": "self-scan-csv-formula-injection",
                    "severity": "high",
                    "category": "payload",
                    "url": "report-format://csv",
                    "description": (
                        f"The csv report renderer wrote a finding field starting with "
                        f"a formula-trigger character ({payload!r}) without "
                        "neutralizing it -- opening this report in Excel/Sheets could "
                        "execute attacker-controlled content sourced from the scanned "
                        "target's own responses (CVE-class: CSV injection)."
                    ),
                    "evidence": payload,
                }
            )
    return findings


def run_self_scan(formats: list[str] | None = None) -> dict:
    """Renders synthetic hostile findings through every report format and
    returns a crawl-doc-shaped result (same `{"target", "findings"}`
    shape as any other scan output) so it can flow through the same
    `shroodler diff --gate` / CI machinery as a real scan."""
    from shroodler.report import render

    fmts = formats or ["html", "markdown", "sarif", "junit", "csv"]
    findings: list[dict] = []
    for fmt in fmts:
        if fmt in ("html", "markdown"):
            findings.extend(_check_html_escaping(fmt, render))
        elif fmt == "sarif":
            findings.extend(_check_well_formed(fmt, render, json.loads))
        elif fmt == "junit":
            findings.extend(_check_well_formed(fmt, render, ET.fromstring))
        elif fmt == "csv":
            findings.extend(_check_csv_formula_injection(render))
    return {"target": "self-scan://report-renderers", "findings": findings}
