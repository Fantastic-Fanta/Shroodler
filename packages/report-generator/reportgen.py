from __future__ import annotations

import csv
import html
import io
import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


def templates_dir() -> Path:
    here = Path(__file__).resolve().parent
    return here / "templates"


def _env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(templates_dir())),
        autoescape=select_autoescape(["html", "j2"]),
    )


def render_html(doc: dict) -> str:
    findings = []
    for f in doc.get("findings", []):
        item = dict(f)
        item["severity_rank"] = SEVERITY_RANK.get(f.get("severity", "info"), 9)
        findings.append(item)
    tmpl = _env().get_template("report.html.j2")
    return tmpl.render(
        target=doc.get("target", ""),
        crawler=doc.get("crawler", {}),
        pages=doc.get("pages", []),
        findings=findings,
    )


def render_csv(doc: dict) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=["severity", "id", "category", "url", "description", "evidence"],
    )
    writer.writeheader()
    ordered = sorted(
        doc.get("findings", []),
        key=lambda f: SEVERITY_RANK.get(f.get("severity", "info"), 9),
    )
    for f in ordered:
        writer.writerow(
            {
                "severity": f.get("severity", ""),
                "id": f.get("id", ""),
                "category": f.get("category", ""),
                "url": f.get("url", ""),
                "description": f.get("description", ""),
                "evidence": f.get("evidence") or "",
            }
        )
    return buf.getvalue()


SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def render_sarif(doc: dict, *, results: list[dict] | None = None) -> str:
    findings = results if results is not None else list(doc.get("findings") or [])
    crawler = doc.get("crawler") or {}
    rules = []
    seen = set()
    for f in findings:
        rid = f.get("id") or "finding"
        if rid in seen:
            continue
        seen.add(rid)
        rules.append(
            {
                "id": rid,
                "shortDescription": {"text": rid},
                "fullDescription": {"text": f.get("description") or rid},
            }
        )
    sarif_results = []
    for f in findings:
        uri = f.get("url") or doc.get("target") or "about:blank"
        sarif_results.append(
            {
                "ruleId": f.get("id") or "finding",
                "level": SARIF_LEVEL.get(f.get("severity", "info"), "note"),
                "message": {"text": f.get("description") or f.get("id") or ""},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                        }
                    }
                ],
            }
        )
    payload = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": crawler.get("name") or "shroodler",
                        "version": crawler.get("version") or "0.1.0",
                        "rules": rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(payload, indent=2) + "\n"


def _xml(text: str) -> str:
    return html.escape(str(text), quote=True)


def render_junit(doc: dict, *, failures: list[dict] | None = None, suite: str = "shroodler") -> str:
    rows = failures if failures is not None else list(doc.get("findings") or [])
    tests = max(len(rows), 1)
    fails = len(rows)
    buf = io.StringIO()
    buf.write('<?xml version="1.0" encoding="UTF-8"?>\n')
    buf.write(
        f'<testsuite name="{_xml(suite)}" tests="{tests}" failures="{fails}" errors="0">\n'
    )
    if not rows:
        buf.write('  <testcase classname="shroodler" name="ok"/>\n')
    for f in rows:
        name = f"{f.get('id', '')} {f.get('url', '')}".strip() or "finding"
        classname = f.get("category") or "finding"
        message = f.get("description") or name
        evidence = f.get("evidence") or message
        buf.write(
            f'  <testcase classname="{_xml(classname)}" name="{_xml(name)}">\n'
            f'    <failure message="{_xml(message)}">{_xml(evidence)}</failure>\n'
            f"  </testcase>\n"
        )
    buf.write("</testsuite>\n")
    return buf.getvalue()


def render_diff_junit(errors: list[str]) -> str:
    rows = [{"id": "diff", "category": "diff", "url": "", "description": e, "evidence": e} for e in errors]
    return render_junit({"findings": rows}, failures=rows, suite="shroodler-diff")


def render_diff_sarif(errors: list[str]) -> str:
    findings = [
        {
            "id": "diff",
            "severity": "high",
            "category": "diff",
            "url": "",
            "description": e,
        }
        for e in errors
    ]
    return render_sarif({"crawler": {"name": "shroodler", "version": "0.1.0"}, "findings": findings})


def render(doc: dict, fmt: str) -> str:
    if fmt == "html":
        return render_html(doc)
    if fmt == "csv":
        return render_csv(doc)
    if fmt == "sarif":
        return render_sarif(doc)
    if fmt == "junit":
        return render_junit(doc)
    raise ValueError(f"unsupported format {fmt}")


def render_file(path: str | Path, fmt: str) -> str:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    return render(doc, fmt)
