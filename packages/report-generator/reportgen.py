from __future__ import annotations

import csv
import html
import io
import json
from pathlib import Path
from urllib.parse import urlparse

from cost_of_attack import cost_of_attack_for
from jinja2 import Environment, FileSystemLoader, select_autoescape
from remediation import remediation_for
from risk_score import compute_risk_score

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


def _enrich_doc(doc: dict) -> dict:
    """Add chain findings and cluster repeating header rows for display."""
    findings = [dict(f) for f in (doc.get("findings") or [])]
    try:
        from shroodler.chains import chain_findings, collapse_systemic_findings

        extra = chain_findings(findings, doc.get("pages") or [])
        existing = {(f.get("id"), f.get("url")) for f in findings}
        for item in extra:
            row = item.model_dump(exclude_none=True)
            if (row.get("id"), row.get("url")) not in existing:
                findings.append(row)
        findings = collapse_systemic_findings(findings)
    except ImportError:
        pass
    out = dict(doc)
    out["findings"] = findings
    return out


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
                "remediation": remediation_for(fid, f.get("category", "")),
                "confidence": f.get("confidence"),
                "cost_of_attack": f.get("cost_of_attack")
                or cost_of_attack_for(fid, f.get("category", "")),
                "urls": [],
            }
            order.append(fid)
        groups[fid]["urls"].append(f.get("url", ""))
    out = [dict(groups[fid], count=len(groups[fid]["urls"])) for fid in order]
    out.sort(key=lambda g: (g["severity_rank"], -g["count"]))
    return out


def render_html(doc: dict) -> str:
    doc = _enrich_doc(doc)
    findings = []
    for f in doc.get("findings", []):
        item = dict(f)
        item["severity_rank"] = SEVERITY_RANK.get(f.get("severity", "info"), 9)
        item["cost_of_attack"] = f.get("cost_of_attack") or cost_of_attack_for(
            f.get("id", ""), f.get("category", "")
        )
        findings.append(item)
    grouped = group_findings(findings)
    tmpl = _env().get_template("report.html.j2")
    return tmpl.render(
        target=doc.get("target", ""),
        crawler=doc.get("crawler", {}),
        pages=doc.get("pages", []),
        findings=findings,
        grouped=grouped,
        risk=compute_risk_score(grouped),
    )


_CSV_FORMULA_TRIGGERS = ("=", "+", "-", "@")


def _csv_safe(value: str) -> str:
    """Neutralize CSV/"formula" injection: Excel/Sheets treats a cell
    value starting with =, +, -, or @ as a formula to evaluate when the
    file is opened, which can execute attacker-controlled content --
    here, content sourced from the SCANNED TARGET's own responses (a
    crawled URL, a reflected value ending up in `description`/`evidence`).
    Prefixing with a single-quote is the standard mitigation (OWASP CSV
    Injection guidance): most spreadsheet apps treat a leading `'` as
    "the rest of this is plain text", so the formula never evaluates.
    """
    text = str(value)
    if text.startswith(_CSV_FORMULA_TRIGGERS):
        return "'" + text
    return text


def render_csv(doc: dict) -> str:
    doc = _enrich_doc(doc)
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=[
            "severity",
            "id",
            "category",
            "url",
            "description",
            "evidence",
            "confidence",
            "cost_of_attack",
        ],
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
                "url": _csv_safe(f.get("url", "")),
                "description": _csv_safe(f.get("description", "")),
                "evidence": _csv_safe(f.get("evidence") or ""),
                "confidence": f.get("confidence") or "",
                "cost_of_attack": f.get("cost_of_attack")
                or cost_of_attack_for(f.get("id", ""), f.get("category", "")),
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

_SARIF_LEVEL_TO_SEV = {
    "error": "high",
    "warning": "medium",
    "note": "info",
    "none": "info",
}

_SARIF_PROP_SEV = {
    "critical": "critical",
    "error": "high",
    "high": "high",
    "warning": "medium",
    "medium": "medium",
    "note": "info",
    "info": "info",
    "informational": "info",
    "low": "low",
}


def _sarif_severity(result: dict, level: str) -> str:
    props = result.get("properties") if isinstance(result.get("properties"), dict) else {}
    for key in ("severity", "problem.severity", "security-severity"):
        raw = props.get(key)
        if isinstance(raw, str) and raw.lower() in _SARIF_PROP_SEV:
            return _SARIF_PROP_SEV[raw.lower()]
        if isinstance(raw, (int, float)):
            # GitHub-style 0.0–10.0 security-severity
            score = float(raw)
            if score >= 9:
                return "critical"
            if score >= 7:
                return "high"
            if score >= 4:
                return "medium"
            if score > 0:
                return "low"
            return "info"
    return _SARIF_LEVEL_TO_SEV.get((level or "note").lower(), "info")


def _sarif_message(result: dict) -> str:
    message = result.get("message")
    if isinstance(message, dict):
        text = message.get("text") or message.get("markdown") or ""
        return str(text)
    if isinstance(message, str):
        return message
    return ""


def _sarif_location_url(result: dict, default_url: str) -> str:
    locations = result.get("locations") or []
    if not isinstance(locations, list):
        locations = []
    for loc in locations:
        if not isinstance(loc, dict):
            continue
        physical = loc.get("physicalLocation")
        if not isinstance(physical, dict):
            continue
        artifact = physical.get("artifactLocation")
        uri = ""
        if isinstance(artifact, dict):
            uri = str(artifact.get("uri") or "")
        region = physical.get("region") if isinstance(physical.get("region"), dict) else {}
        line = region.get("startLine")
        if uri and line:
            return f"{uri}#L{line}"
        if uri:
            return uri
    return default_url or "sarif"


def findings_from_sarif(doc: dict, *, default_url: str = "") -> list[dict]:
    """Fold a SARIF 2.x document into Shroodler finding dicts.

    Translation only — does not re-run Semgrep/CodeQL/Slither. Unknown
    extra SARIF fields are dropped so the result validates against the
    finding schema.
    """
    runs = doc.get("runs") or []
    if not isinstance(runs, list):
        return []
    out: list[dict] = []
    for run in runs:
        if not isinstance(run, dict):
            continue
        results = run.get("results") or []
        if not isinstance(results, list):
            continue
        for result in results:
            if not isinstance(result, dict):
                continue
            rule_id = str(result.get("ruleId") or result.get("ruleID") or "sarif-finding")
            level = str(result.get("level") or "note")
            url = _sarif_location_url(result, default_url)
            desc = _sarif_message(result) or rule_id
            out.append(
                {
                    "id": rule_id,
                    "severity": _sarif_severity(result, level),
                    "category": "sast",
                    "url": url,
                    "description": desc,
                    "evidence": url,
                    "confidence": "probable",
                }
            )
    return out


def merge_findings(base: list, extra: list) -> list:
    """Append extra findings that are not already present by (id, url)."""
    seen = {(f.get("id"), f.get("url")) for f in base if isinstance(f, dict)}
    out = list(base)
    for finding in extra:
        if not isinstance(finding, dict):
            continue
        key = (finding.get("id"), finding.get("url"))
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    return out


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


def _md_inline_code_safe(value: str) -> str:
    """HTML-escape a value AND neutralize backticks before it's placed
    inside a single-backtick Markdown code span. html.escape() alone
    handles `&`/`<`/`>`/quotes but leaves backticks untouched -- a value
    containing one could prematurely close the span and let the rest of
    the line be parsed as ordinary Markdown structure instead of literal
    text, on content that (for url/evidence/id) may originate from the
    scanned target's own responses."""
    return html.escape(str(value)).replace("`", "'")


def render_markdown(doc: dict) -> str:
    doc = _enrich_doc(doc)
    findings = list(doc.get("findings") or [])
    crawler = doc.get("crawler") or {}
    target = _md_inline_code_safe(doc.get("target") or "")
    pages = doc.get("pages") or []
    # crawler.name/version/mode come from the crawl doc like every other
    # field checked here -- not target-reflected in the crawlers this
    # codebase ships today, but this function has no way to enforce
    # that, and the whole point of the self-scan work this escaping
    # belongs to is not leaving that kind of assumption unenforced.
    name = html.escape(crawler.get("name") or "")
    version = html.escape(crawler.get("version") or "")
    mode = html.escape(crawler.get("mode") or "")
    risk = compute_risk_score(group_findings(findings))
    counts = risk["severity_counts"]
    risk_line = (
        f"**Grade: {risk['grade']}** ({risk['score']} risk points) -- "
        f"{counts['critical']} critical, {counts['high']} high, {counts['medium']} medium, "
        f"{counts['low']} low, {counts['info']} info "
        "(by distinct finding type, not raw per-page instance count; floored by the "
        "single worst severity present)"
    )
    if risk["partial_coverage"]:
        risk_line += (
            ". **This scan reports it could not fully test the target** (a WAF "
            "challenge, a skipped probe, or a truncated redirect chain appears below) "
            "-- treat this grade as a lower bound, not a clean bill of health"
        )
    lines = [
        "# Shroodler report",
        "",
        f"Target: `{target}`",
        f"Crawler: {name} {version} ({mode})".strip(),
        f"{len(pages)} pages · {len(findings)} findings",
        "",
        risk_line,
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
            # url/description/evidence/id are free text sourced from the
            # SCANNED TARGET's own responses (a crawled URL, a reflected
            # value) -- HTML-escaped before interpolation because a
            # Markdown report is commonly rendered as rich text
            # downstream (GitHub, a chat client, an editor preview), and
            # CommonMark passes raw inline HTML straight through by
            # design. Without this, a target that reflects
            # "<script>...</script>" into a crawled page turns this
            # report into a stored-XSS delivery vector wherever it's
            # rendered.
            #
            # html.escape() alone isn't enough for the three fields
            # wrapped in single-backtick code spans (url, evidence, id):
            # it doesn't touch backtick characters, so a value containing
            # one could still prematurely close the span and let the
            # rest of the line be parsed as ordinary Markdown structure
            # instead of literal text. `_md_inline_code_safe` neutralizes
            # backticks on top of the HTML-escaping for exactly those
            # three fields; `description` (rendered as plain prose, not
            # inside a code span) only needs the HTML-escaping.
            #
            # `id` is drawn from a fixed internal catalog today (no
            # extractor/pack builds one from scanned-target content), so
            # this is defense in depth, not a currently-exploitable gap
            # -- kept safe anyway so a future dynamically-built id
            # doesn't silently reopen this bug class.
            fid = _md_inline_code_safe(f.get("id") or "finding")
            url = _md_inline_code_safe(f.get("url") or "")
            desc = html.escape(f.get("description") or "")
            lines.append(f"### `{fid}`")
            lines.append("")
            lines.append(f"- URL: `{url}`")
            lines.append(f"- Description: {desc}")
            ev = format_evidence(f.get("evidence"))
            if ev:
                lines.append(f"- Evidence: `{_md_inline_code_safe(ev)}`")
            # confidence/cost_of_attack are drawn from fixed enums today
            # (never target-reflected), but escaped anyway for the same
            # reason id is: consistent with this function's own stated
            # position that a renderer's escaping shouldn't silently
            # depend on current data provenance staying true forever.
            confidence = f.get("confidence")
            if confidence:
                lines.append(f"- Confidence: {html.escape(str(confidence))}")
            cost = f.get("cost_of_attack") or cost_of_attack_for(fid, f.get("category", ""))
            lines.append(f"- Cost of attack: {html.escape(str(cost))}")
            lines.append(f"- Remediation: {remediation_for(fid, f.get('category', ''))}")
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
