"""Score crawl findings by exploitability so a researcher can see what
is worth submitting, with enough context to draft a bounty report.

Pure stdlib. No LLM. Finding has no reproduction / param_name / tags
fields — those are parsed from description, evidence, and the URL.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlparse

from shroodler.models import Finding
from shroodler.program import url_to_pattern

_PARAM_RE = re.compile(r"(?:param|parameter|field|arg)=([^\s&]+)")
_CURL_RE = re.compile(r"(curl\b.+)", re.IGNORECASE | re.DOTALL)

# (id prefix/stem, base exploitability, human vuln type)
_EXPLOIT_RULES: tuple[tuple[str, int, str], ...] = (
    ("login-recipe-failed", 0, "Login Recipe Failed"),
    ("js-api-endpoint", 10, "JS API Endpoint"),
    ("js-hardcoded-secret", 85, "Hardcoded Secret"),
    ("js-client-side-jwt", 60, "Client-Side JWT"),
    ("idor-cross-account", 90, "Cross-Account IDOR"),
    ("jwt-alg-none", 85, "JWT Algorithm None"),
    ("jwt-rs256-hs256", 80, "JWT Algorithm Confusion"),
    ("xss-stored", 85, "Stored XSS"),
    ("xss-reflected", 65, "Reflected XSS"),
    ("open-redirect", 50, "Open Redirect"),
    ("host-header", 45, "Host Header Injection"),
    ("mass-assignment", 70, "Mass Assignment"),
    ("prototype-pollut", 60, "Prototype Pollution"),
    ("ssrf", 75, "SSRF"),
    ("ssti", 80, "SSTI"),
    ("xxe", 75, "XXE"),
    ("sqli", 80, "SQL Injection"),
    ("graphql", 55, "GraphQL"),
    ("crlf", 55, "CRLF Injection"),
)

_ID_ALIASES: dict[str, tuple[str, ...]] = {
    "jwt-rs256-hs256": ("jwt-algorithm-confusion",),
}

_DEFAULT_VULN = "Finding"
_DEFAULT_BASE = 30

_VALID_CATEGORY = {
    "header",
    "cookie",
    "secret",
    "exposed-file",
    "js-endpoint",
    "verbose-error",
    "autocomplete",
    "payload",
    "scan-note",
    "auth",
    "waf-challenge",
    "subresource",
    "tls",
    "smart-contract",
    "sast",
}
_VALID_SEVERITY = {"info", "low", "medium", "high", "critical"}
_VALID_CONFIDENCE = {"confirmed", "probable", "heuristic"}


@dataclass
class TriageResult:
    finding: Finding
    exploitability: int
    confidence: int
    worth_submitting: bool
    reasons: list[str]
    suggested_title: str
    suggested_severity: str
    reproduction_steps: list[str]


def _id_matches(fid: str, pattern: str) -> bool:
    """Prefix/contains match so `sqli` matches sqli-*, `xss-reflected`
    matches xss-reflected-*, and `js-client-side-jwt-decode` matches
    js-client-side-jwt.
    """
    fid = (fid or "").strip().lower()
    stem = (pattern or "").strip().lower().rstrip("*")
    if not fid or not stem:
        return False
    if fid == stem or fid.startswith(stem + "-") or fid.startswith(stem):
        return True
    for alias in _ID_ALIASES.get(stem, ()):
        if fid == alias or fid.startswith(alias + "-") or fid.startswith(alias):
            return True
    return False


def _attr(finding: Any, name: str, default: Any = None) -> Any:
    if isinstance(finding, dict):
        return finding.get(name, default)
    return getattr(finding, name, default)


def _fid(finding: Any) -> str:
    return str(_attr(finding, "id", "") or "")


def _text_of(finding: Any, *names: str) -> str:
    parts: list[str] = []
    for name in names:
        val = _attr(finding, name, None)
        if val:
            parts.append(str(val))
    return " ".join(parts)


def _family(fid: str) -> tuple[int, str]:
    for stem, base, label in _EXPLOIT_RULES:
        if _id_matches(fid, stem):
            return base, label
    return _DEFAULT_BASE, _DEFAULT_VULN


def _family_prefix(fid: str) -> str:
    for stem, _, _ in _EXPLOIT_RULES:
        if _id_matches(fid, stem):
            return stem
    return (fid or "").split("-")[0] if fid else ""


def _is_error_sqli(fid: str) -> bool:
    low = (fid or "").lower()
    if not _id_matches(fid, "sqli"):
        return False
    if any(token in low for token in ("time", "boolean", "blind", "oob")):
        return False
    return True


def _param_name(finding: Any) -> str | None:
    explicit = _attr(finding, "param_name", None) or _attr(finding, "param", None)
    if explicit:
        text = str(explicit).strip()
        if text:
            return text
    evidence = str(_attr(finding, "evidence", "") or "")
    match = _PARAM_RE.search(evidence)
    if match:
        return match.group(1)
    url = str(_attr(finding, "url", "") or "")
    qs = parse_qsl(urlparse(url).query, keep_blank_values=True)
    if qs:
        return qs[0][0]
    desc = str(_attr(finding, "description", "") or "")
    match = _PARAM_RE.search(desc)
    if match:
        return match.group(1)
    return None


def _reproduction_text(finding: Any) -> str | None:
    repro = _attr(finding, "reproduction", None)
    if isinstance(repro, str) and repro.strip():
        return repro.strip()
    for raw in (
        str(_attr(finding, "description", "") or ""),
        str(_attr(finding, "evidence", "") or ""),
    ):
        if "curl" not in raw.lower():
            continue
        match = _CURL_RE.search(raw)
        chunk = (match.group(1) if match else raw).strip()
        line = chunk.split("\n")[0].strip()
        if line:
            return line
    return None


def _has_reproduction(finding: Any) -> bool:
    repro = _attr(finding, "reproduction", None)
    if isinstance(repro, str) and len(repro) > 20:
        return True
    for raw in (
        str(_attr(finding, "description", "") or ""),
        str(_attr(finding, "evidence", "") or ""),
    ):
        if "curl" in raw.lower() and len(raw) > 20:
            return True
    return False


def _tags(finding: Any) -> list[str]:
    tags = _attr(finding, "tags", None)
    if not tags:
        return []
    if isinstance(tags, str):
        return [tags]
    return [str(t) for t in tags]


def _path_of(url: str) -> str:
    path = urlparse(url or "").path or "/"
    return path if path.startswith("/") else "/" + path


def severity_label(score: int) -> str:
    """Map exploitability to Bugcrowd/HackerOne severity labels."""
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 50:
        return "medium"
    if score >= 30:
        return "low"
    return "informational"


def _clamp(value: int) -> int:
    return max(0, min(100, int(value)))


def _confidence_base(fid: str) -> tuple[int, str]:
    if _id_matches(fid, "sqli-time-based"):
        return 60, "time-based SQLi"
    if _id_matches(fid, "sqli-boolean"):
        return 75, "boolean SQLi"
    if _id_matches(fid, "sqli-error") or _is_error_sqli(fid):
        return 90, "error-based SQLi"
    if _id_matches(fid, "ssrf-cloud-meta"):
        return 95, "cloud-metadata SSRF"
    if _id_matches(fid, "ssrf-oob"):
        return 85, "OOB SSRF"
    if _id_matches(fid, "xss"):
        return 85, "XSS"
    if _id_matches(fid, "idor"):
        return 95, "IDOR"
    if _id_matches(fid, "jwt"):
        return 90, "JWT"
    return 70, "default"


def _as_finding(item: Any) -> Finding | None:
    if isinstance(item, Finding):
        return item
    if not isinstance(item, dict):
        return None
    category = str(item.get("category") or "scan-note")
    if category not in _VALID_CATEGORY:
        category = "scan-note"
    severity = str(item.get("severity") or "info")
    if severity not in _VALID_SEVERITY:
        severity = "info"
    confidence = item.get("confidence")
    if confidence not in _VALID_CONFIDENCE:
        confidence = None
    try:
        return Finding(
            id=str(item.get("id") or "unknown"),
            severity=severity,  # type: ignore[arg-type]
            category=category,  # type: ignore[arg-type]
            url=str(item.get("url") or "http://unknown"),
            description=str(item.get("description") or ""),
            evidence=item.get("evidence"),
            confidence=confidence,
        )
    except Exception:
        return None


def findings_from_doc(doc: Any) -> list[Finding]:
    if isinstance(doc, list):
        raw = doc
    elif isinstance(doc, dict):
        raw = doc.get("findings") or []
    else:
        raw = []
    out: list[Finding] = []
    for item in raw:
        finding = _as_finding(item)
        if finding is not None:
            out.append(finding)
    return out


def result_to_dict(result: TriageResult) -> dict[str, Any]:
    finding = result.finding
    dump = getattr(finding, "model_dump", None)
    if callable(dump):
        try:
            finding_doc = dump(mode="json")
        except TypeError:
            finding_doc = dump()
    elif isinstance(finding, dict):
        finding_doc = dict(finding)
    else:
        finding_doc = {
            "id": _fid(finding),
            "severity": _attr(finding, "severity", "info"),
            "category": _attr(finding, "category", "scan-note"),
            "url": _attr(finding, "url", ""),
            "description": _attr(finding, "description", ""),
            "evidence": _attr(finding, "evidence", None),
            "confidence": _attr(finding, "confidence", None),
        }
    return {
        "finding": finding_doc,
        "exploitability": result.exploitability,
        "confidence": result.confidence,
        "worth_submitting": result.worth_submitting,
        "reasons": list(result.reasons),
        "suggested_title": result.suggested_title,
        "suggested_severity": result.suggested_severity,
        "reproduction_steps": list(result.reproduction_steps),
    }


def format_text_table(results: list[TriageResult]) -> str:
    if not results:
        return "No findings.\n"
    headers = ("ID", "SEVERITY", "EXPLOITABILITY", "CONFIDENCE", "WORTH", "TITLE")
    rows: list[list[str]] = []
    for result in results:
        title = result.suggested_title or ""
        if len(title) > 60:
            title = title[:60]
        rows.append(
            [
                _fid(result.finding),
                str(_attr(result.finding, "severity", "") or ""),
                str(result.exploitability),
                str(result.confidence),
                "yes" if result.worth_submitting else "no",
                title,
            ]
        )
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    lines = ["  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))]
    lines.append("  ".join("-" * w for w in widths))
    for row in rows:
        lines.append("  ".join(row[i].ljust(widths[i]) for i in range(len(headers))))
    return "\n".join(lines) + "\n"


def _suggested_title(vuln_type: str, url: str, param: str | None) -> str:
    path = _path_of(url)
    param_bit = f"{param} parameter" if param else "unknown parameter"
    return f"{vuln_type} on {path} via {param_bit}"


def _reproduction_steps(
    finding: Any, vuln_type: str, url: str
) -> list[str]:
    steps: list[str] = []
    tags = [t.lower() for t in _tags(finding)]
    if "auth" in tags:
        steps.append("Authenticate as a normal user account")
    repro = _reproduction_text(finding)
    if repro:
        steps.append(f"Send the following request: {repro}")
    else:
        steps.append(f"Replay the request to {url}")
    evidence = str(_attr(finding, "evidence", "") or "")
    if evidence:
        steps.append(f"Observe: {evidence[:200]}")
    steps.append(f"Verify the response confirms {vuln_type}")
    return steps


def score_finding(finding: Finding | Any) -> TriageResult:
    parsed = _as_finding(finding) or finding
    source = finding
    fid = _fid(source) or _fid(parsed)
    url = str(_attr(source, "url", "") or _attr(parsed, "url", "") or "")
    severity = str(_attr(source, "severity", None) or _attr(parsed, "severity", "info") or "info")
    evidence_text = _text_of(source, "evidence", "description").lower()
    base, vuln_type = _family(fid)
    reasons = [f"base {base} for {vuln_type}"]
    score = base
    if _id_matches(fid, "sqli") and ("sleep" in evidence_text or "waitfor" in evidence_text):
        score += 10
        reasons.append("+10 time-based sleep/waitfor in evidence")
    if _id_matches(fid, "ssrf") and "169.254" in evidence_text:
        score += 10
        reasons.append("+10 cloud metadata (169.254) in evidence")
    if severity == "critical":
        score += 10
        reasons.append("+10 severity critical")
    elif severity == "high":
        score += 5
        reasons.append("+5 severity high")
    elif severity in {"low", "info"}:
        score -= 10
        reasons.append(f"-10 severity {severity}")
    if _has_reproduction(source):
        score += 5
        reasons.append("+5 reproduction present")
    param = _param_name(source)
    if param:
        score += 5
        reasons.append(f"+5 named parameter ({param})")
    if "false-positive" in _tags(source):
        score -= 15
        reasons.append("-15 false-positive tag")
    exploitability = _clamp(score)

    conf, conf_why = _confidence_base(fid)
    reasons.append(f"confidence base {conf} ({conf_why})")
    low_id = fid.lower()
    if "blind" in low_id or "oob" in low_id:
        conf -= 10
        reasons.append("-10 blind/oob in finding id")
    confidence = _clamp(conf)

    worth = exploitability >= 50 and confidence >= 65
    stored = parsed if isinstance(parsed, Finding) else Finding(
        id=fid or "unknown",
        severity=severity if severity in _VALID_SEVERITY else "info",  # type: ignore[arg-type]
        category="payload",
        url=url or "http://unknown",
        description=str(_attr(source, "description", "") or ""),
        evidence=_attr(source, "evidence", None),
    )
    return TriageResult(
        finding=stored,
        exploitability=exploitability,
        confidence=confidence,
        worth_submitting=worth,
        reasons=reasons,
        suggested_title=_suggested_title(vuln_type, url, param),
        suggested_severity=severity_label(exploitability),
        reproduction_steps=_reproduction_steps(source, vuln_type, url),
    )


def triage_findings(
    findings: list[Finding],
    min_exploitability: int = 50,
    min_confidence: int = 65,
) -> list[TriageResult]:
    """Score every finding, sorted by exploitability desc.

    Dedup: same (id_prefix, url_path_pattern, param_name) keeps the
    highest-exploitability result; the rest are marked not worth submitting.
    """
    results = [score_finding(item) for item in (findings or [])]
    for result in results:
        result.worth_submitting = (
            result.exploitability >= min_exploitability
            and result.confidence >= min_confidence
        )
    best: dict[tuple[str, str, str], TriageResult] = {}
    for result in results:
        key = (
            _family_prefix(_fid(result.finding)),
            url_to_pattern(str(_attr(result.finding, "url", "") or "")),
            _param_name(result.finding) or "",
        )
        prev = best.get(key)
        if prev is None:
            best[key] = result
            continue
        if result.exploitability > prev.exploitability:
            prev.worth_submitting = False
            best[key] = result
        else:
            result.worth_submitting = False
    results.sort(key=lambda item: item.exploitability, reverse=True)
    return results
