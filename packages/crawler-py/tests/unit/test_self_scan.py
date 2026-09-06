from __future__ import annotations

from shroodler.self_scan import run_self_scan


def test_self_scan_returns_crawl_doc_shape():
    result = run_self_scan(["html"])
    assert "target" in result
    assert "findings" in result


def test_self_scan_default_formats_exclude_json():
    # json bypasses the template renderers entirely (plain json.dumps)
    # and isn't supposed to be HTML-escaped -- checking it here would
    # only ever produce false positives.
    result = run_self_scan()
    assert not any(f["url"] == "report-format://json" for f in result["findings"])


def test_self_scan_detects_a_crashing_renderer(monkeypatch):
    def boom(doc, fmt):
        raise ValueError("synthetic crash")

    monkeypatch.setattr("shroodler.report.render", boom)
    result = run_self_scan(["html"])
    assert any(f["id"] == "self-scan-renderer-crash" for f in result["findings"])


def test_self_scan_detects_unescaped_echo(monkeypatch):
    def naive_render(doc, fmt):
        # Simulates exactly the bug class this tool is meant to catch:
        # an f-string report renderer with no HTML escaping.
        return doc["findings"][0]["evidence"]

    monkeypatch.setattr("shroodler.report.render", naive_render)
    result = run_self_scan(["html"])
    ids = {f["id"] for f in result["findings"]}
    assert "self-scan-unescaped-html" in ids
    assert all(f["severity"] == "critical" for f in result["findings"])


def test_self_scan_html_format_actually_escapes_today():
    # A real regression test for the current renderer, not just the
    # self-scan mechanism: today's Jinja-autoescaped HTML template must
    # not let a raw <script> tag through unescaped.
    result = run_self_scan(["html"])
    assert result["findings"] == []


def test_self_scan_markdown_format_escapes_today():
    result = run_self_scan(["markdown"])
    assert result["findings"] == []


def test_self_scan_csv_format_neutralizes_formulas_today():
    result = run_self_scan(["csv"])
    assert result["findings"] == []


def test_self_scan_sarif_and_junit_stay_well_formed_today():
    result = run_self_scan(["sarif", "junit"])
    assert result["findings"] == []


def test_self_scan_detects_malformed_sarif_output(monkeypatch):
    def broken_json_render(doc, fmt):
        return "{not valid json"

    monkeypatch.setattr("shroodler.report.render", broken_json_render)
    result = run_self_scan(["sarif"])
    assert any(f["id"] == "self-scan-malformed-output" for f in result["findings"])


def test_self_scan_detects_malformed_junit_xml(monkeypatch):
    def naive_xml_render(doc, fmt):
        # Unescaped "<" breaks XML well-formedness.
        return f"<testsuite>{doc['findings'][0]['evidence']}</testsuite>"

    monkeypatch.setattr("shroodler.report.render", naive_xml_render)
    result = run_self_scan(["junit"])
    assert any(f["id"] == "self-scan-malformed-output" for f in result["findings"])


def test_self_scan_detects_unneutralized_csv_formula(monkeypatch):
    def naive_csv_render(doc, fmt):
        return f"id,evidence\nx,{doc['findings'][0]['evidence']}\n"

    monkeypatch.setattr("shroodler.report.render", naive_csv_render)
    result = run_self_scan(["csv"])
    assert any(f["id"] == "self-scan-csv-formula-injection" for f in result["findings"])
