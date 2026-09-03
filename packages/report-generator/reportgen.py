from __future__ import annotations

import csv
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


def render(doc: dict, fmt: str) -> str:
    if fmt == "html":
        return render_html(doc)
    if fmt == "csv":
        return render_csv(doc)
    raise ValueError(f"unsupported format {fmt}")


def render_file(path: str | Path, fmt: str) -> str:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    return render(doc, fmt)
