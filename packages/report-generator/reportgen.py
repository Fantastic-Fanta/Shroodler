from __future__ import annotations

import csv
import html
import io
import json
from pathlib import Path
from urllib.parse import urlparse

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


def group_findings(findings: list[dict]) -> list[dict]:
    """Roll up findings that share an id, for a scannable summary.

    A single misconfigured header on a 400-page crawl otherwise produces
    400 near-identical detail rows; this groups them by id so the report
    stays usable at scale while the detail table below keeps every row.
    """
    groups: dict[str, dict] = {}
    order: list[str] = []
    for f in findings:
        fid = f.get("id", "")
        if fid not in groups:
            groups[fid] = {
                "id": fid,
                "severity": f.get("severity", "info"),
                "severity_rank": SEVERITY_RANK.get(f.get("severity", "info"), 9),
                "description": f.get("description", ""),
                "urls": [],
            }
            order.append(fid)
        groups[fid]["urls"].append(f.get("url", ""))
    out = [dict(groups[fid], count=len(groups[fid]["urls"])) for fid in order]
    out.sort(key=lambda g: (g["severity_rank"], -g["count"]))
    return out


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
        grouped=group_findings(findings),
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

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def format_evidence(value) -> str:
    """Redact compact tokens and truncate long snippets, matching HTML's caution."""
    if value is None:
        return ""
    text = str(value)
    if not text or text == "None":
        return ""
    compact = text.strip()
    if len(compact) > 8 and not any(ch.isspace() or ch == "/" for ch in compact):
        return compact[:4] + "************" + compact[-4:]
    if len(text) > 80:
        return text[:76] + "…"
    return text


def _sarif_artifact_uri(url: str) -> str:
    """Turn a live HTTP(S) finding URL into a relative artifactLocation.uri.

    GitHub code-scanning's SARIF ingestion expects artifactLocation.uri to be
    relative (no scheme), since it is normally a path inside the repo. DAST
    findings don't have a repo file, so we encode host+path as a relative
    pseudo-path and record the real URL under uriBaseId "SCANTARGET" (see
    the run-level originalUriBaseIds below) plus properties.target_url, per
    the SARIF spec's documented pattern for non-file-based results.
    """
    parsed = urlparse(url)
    if not parsed.scheme:
        return url.lstrip("/") or "target"
    host = (parsed.netloc or "target").replace(":", "_")
    path = parsed.path or "/"
    return f"{host}{path}".lstrip("/") or host


def render_sarif(doc: dict, *, results: list[dict] | None = None) -> str:
    findings = results if results is not None else list(doc.get("findings") or [])
    crawler = doc.get("crawler") or {}
    rules: list[dict] = []
    seen: set[str] = set()
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
                "level": SARIF_LEVEL.get(f.get("severity") or "info", "note"),
                "message": {"text": f.get("description") or f.get("id") or ""},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": _sarif_artifact_uri(uri),
                                "uriBaseId": "SCANTARGET",
                            },
                        }
                    }
                ],
                "properties": {"target_url": uri},
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
                "originalUriBaseIds": {
                    "SCANTARGET": {"uri": (doc.get("target") or "about:blank") + "/"}
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


def render_markdown(doc: dict) -> str:
    findings = list(doc.get("findings") or [])
    crawler = doc.get("crawler") or {}
    target = doc.get("target") or ""
    pages = doc.get("pages") or []
    name = crawler.get("name") or ""
    version = crawler.get("version") or ""
    mode = crawler.get("mode") or ""
    lines = [
        "# Shroodler report",
        "",
        f"Target: `{target}`",
        f"Crawler: {name} {version} ({mode})".strip(),
        f"{len(pages)} pages · {len(findings)} findings",
        "",
    ]
    if not findings:
        lines.append("No findings.")
        lines.append("")
        return "\n".join(lines)

    grouped: dict[str, list] = {s: [] for s in SEVERITY_ORDER}
    for f in findings:
        sev = f.get("severity") or "info"
        grouped.setdefault(sev, []).append(f)

    for sev in list(SEVERITY_ORDER) + [s for s in grouped if s not in SEVERITY_ORDER]:
        rows = grouped.get(sev) or []
        if not rows:
            continue
        lines.append(f"## {sev}")
        lines.append("")
        for f in rows:
            fid = f.get("id") or "finding"
            url = f.get("url") or ""
            desc = f.get("description") or ""
            lines.append(f"### `{fid}`")
            lines.append("")
            lines.append(f"- URL: `{url}`")
            lines.append(f"- Description: {desc}")
            ev = format_evidence(f.get("evidence"))
            if ev:
                lines.append(f"- Evidence: `{ev}`")
            lines.append("")
    return "\n".join(lines)


def render(doc: dict, fmt: str) -> str:
    if fmt == "html":
        return render_html(doc)
    if fmt == "csv":
        return render_csv(doc)
    if fmt == "sarif":
        return render_sarif(doc)
    if fmt == "junit":
        return render_junit(doc)
    if fmt in {"md", "markdown"}:
        return render_markdown(doc)
    raise ValueError(f"unsupported format {fmt}")


def render_file(path: str | Path, fmt: str) -> str:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    return render(doc, fmt)
