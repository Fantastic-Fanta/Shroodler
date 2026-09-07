"""`shroodler ask`: conversational interrogation of scan/report/trend data.

Triaging a 200-finding report by hand is where most DAST tools lose
users; this is a thin query layer over data `trend`/`diff`/`report`
already compute, so a user (or an agent) can ask "show findings reachable
without auth" or "what's new since Tuesday's scan" instead of grepping
JSON.

The default backend is a small, deterministic keyword/intent matcher --
no network call, no API key, works offline, and its behavior is exactly
as testable as the rest of this codebase. Set SHROODLER_ASK_LLM_CMD to
the path of an external program to hand it a richer natural-language
query instead: that program is invoked with the rendered scan context on
stdin and the raw question as argv[1], and must print its answer to
stdout. This keeps the tool honest about which mode answered a given
question (`answered_by` in the result) rather than pretending the
heuristic backend understands free-form English.

Security note for SHROODLER_ASK_LLM_CMD: the scan context piped to that
program's stdin is built from data the scanned TARGET produced --
crawled URLs, header values, HTML comments, secrets findings -- none of
it is trusted input. If the external command is itself an LLM wrapper,
a hostile page can attempt prompt injection through that content the
same way it could through any other tool that feeds live web content to
a model. This module only guarantees the subprocess call itself is safe
(argv-list invocation, no shell); it makes no claim about what the
external program does with the content it's handed.
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass

from shroodler.history import trend_diff

_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

_AUTH_LEAD_IDS = {
    "authz-still-accessible",
    "authz-broken-access-control",
    "idor-adjacent-id-accessible",
    "peer-write-idor",
}


@dataclass
class AskResult:
    answered_by: str
    intent: str
    text: str
    data: dict


def _severity_at_or_above(min_sev: str) -> set[str]:
    if min_sev not in _SEVERITY_ORDER:
        return set(_SEVERITY_ORDER)
    idx = _SEVERITY_ORDER.index(min_sev)
    return set(_SEVERITY_ORDER[idx:])


def _mentioned_severity(query: str) -> str | None:
    for sev in _SEVERITY_ORDER:
        if re.search(rf"\b{sev}\b", query):
            return sev
    return None


def _mentioned_category(query: str, categories: set[str]) -> str | None:
    for cat in categories:
        if re.search(rf"\b{re.escape(cat)}\b", query):
            return cat
    return None


def _summarize_findings(findings: list[dict]) -> dict:
    by_severity: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "unknown")
        by_severity[sev] = by_severity.get(sev, 0) + 1
    return {"total": len(findings), "by_severity": by_severity}


def _render_finding_list(findings: list[dict]) -> str:
    if not findings:
        return "No matching findings."
    lines = [
        f"{f.get('severity', '?'):8s} {f.get('id', '?'):30s} {f.get('url', '')}" for f in findings
    ]
    return "\n".join(lines)


def answer(query: str, scan: dict, *, older_scan: dict | None = None) -> AskResult:
    """Answer `query` against `scan` (a crawl/report document), optionally
    with `older_scan` for "what's new/resolved since" questions."""
    llm_cmd = os.environ.get("SHROODLER_ASK_LLM_CMD")
    if llm_cmd:
        return _answer_via_external(llm_cmd, query, scan, older_scan=older_scan)
    return _answer_heuristic(query, scan, older_scan=older_scan)


def _answer_via_external(cmd: str, query: str, scan: dict, *, older_scan: dict | None) -> AskResult:
    import json

    context = json.dumps({"scan": scan, "older_scan": older_scan})
    proc = subprocess.run(
        [cmd, query],
        input=context,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    return AskResult(
        answered_by="external",
        intent="external",
        text=proc.stdout.strip()
        or f"(external ask command exited {proc.returncode} with no output)",
        data={"returncode": proc.returncode, "stderr": proc.stderr},
    )


def _answer_heuristic(query: str, scan: dict, *, older_scan: dict | None) -> AskResult:
    q = query.lower().strip()
    findings = scan.get("findings", [])
    categories = {f.get("category", "") for f in findings}

    if older_scan is not None and any(kw in q for kw in ("new since", "what's new", "since")):
        trend = trend_diff(older_scan, scan)
        intro = trend["introduced"]
        text = (
            f"{len(intro)} new finding(s) since the older scan:\n"
            + "\n".join(f"{i['id']} @ {i['url']}" for i in intro)
            if intro
            else "No new findings since the older scan."
        )
        return AskResult("heuristic", "new-since", text, {"introduced": intro})

    if older_scan is not None and "resolved" in q:
        trend = trend_diff(older_scan, scan)
        res = trend["resolved"]
        text = (
            f"{len(res)} finding(s) resolved since the older scan:\n"
            + "\n".join(f"{i['id']} @ {i['url']}" for i in res)
            if res
            else "Nothing resolved since the older scan."
        )
        return AskResult("heuristic", "resolved-since", text, {"resolved": res})

    if "without auth" in q or "no auth" in q or "unauthenticated" in q or "reachable" in q:
        matches = [f for f in findings if f.get("id") in _AUTH_LEAD_IDS]
        return AskResult(
            "heuristic",
            "reachable-without-auth",
            _render_finding_list(matches),
            {"findings": matches},
        )

    if any(kw in q for kw in ("how many", "count", "summarize", "summary")):
        summary = _summarize_findings(findings)
        text = f"{summary['total']} finding(s) total: " + ", ".join(
            f"{n} {sev}" for sev, n in sorted(summary["by_severity"].items())
        )
        return AskResult("heuristic", "summary", text, summary)

    sev = _mentioned_severity(q)
    if sev and ("or higher" in q or "or above" in q or "and up" in q):
        wanted = _severity_at_or_above(sev)
        matches = [f for f in findings if f.get("severity") in wanted]
        return AskResult(
            "heuristic",
            "severity-at-or-above",
            _render_finding_list(matches),
            {"findings": matches},
        )
    if sev:
        matches = [f for f in findings if f.get("severity") == sev]
        return AskResult(
            "heuristic", "severity-exact", _render_finding_list(matches), {"findings": matches}
        )

    cat = _mentioned_category(q, categories)
    if cat:
        matches = [f for f in findings if f.get("category") == cat]
        return AskResult(
            "heuristic", "category", _render_finding_list(matches), {"findings": matches}
        )

    return AskResult(
        "heuristic",
        "unrecognized",
        "Could not match this question to a known intent (severity/category filters, "
        "'summary', 'new since'/'resolved' with --since, 'reachable without auth'). "
        "Set SHROODLER_ASK_LLM_CMD to delegate free-form questions to an external model.",
        {"findings": []},
    )
