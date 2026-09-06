"""Attack-path graph report: correlate three things this codebase already
computes separately (crawl structure, authz/IDOR findings, token-entropy
findings) into one artifact instead of a flat finding list -- "this XSS
is reachable in 2 clicks from the homepage; this SQLi needs a session
token this same scan proved guessable" is a very different priority
signal than either finding shown alone. Nobody currently correlates
these; the raw material already exists uniquely in this codebase (a
crawl graph, authz-diff's cross-session results, token_entropy's
guessability scoring) -- this is the highest cost to build of the
speculative ideas, but the pieces are all already there.

Two honesty notes, stated up front because they shape every design
choice below:

1. Neither crawler engine persists a real inter-page link graph into its
   JSON output (no "linked from" field on a page) -- adding one would be
   a crawler/schema change affecting parity between the Python and Go
   engines. Instead, "distance from the target root" is approximated by
   URL PATH DEPTH (segment count), which correlates with click-distance
   in most conventionally-organized sites but is not a real BFS over
   actual discovered links. This is disclosed in every rendered output,
   not just this docstring.
2. "Needs a session token this scan proved guessable" is a same-scan
   correlation, not a proof that a specific finding's exploitation path
   actually routes through that specific token -- it means the scan
   found evidence of at least one weak token AND at least one finding
   whose category suggests session/account context, and surfaces that
   as a hypothesis worth investigating, not a confirmed chain.
"""

from __future__ import annotations

from urllib.parse import urlparse

_TOKEN_WEAKNESS_IDS = {
    "reset-token-sequential",
    "reset-token-small-keyspace",
    "reset-token-short",
    "reset-token-in-url",
}

# Findings whose exploitation plausibly involves session/account context,
# so a same-scan weak-token finding is worth flagging alongside them.
_SESSION_RELEVANT_CATEGORIES = {"auth"}


def _path_depth(url: str) -> int:
    path = urlparse(url).path or "/"
    return len([s for s in path.split("/") if s])


def build_attack_path(doc: dict) -> dict:
    """Returns a report correlating every finding in `doc` with its
    path-depth (reachability proxy) and whether the same scan found
    evidence of a guessable session/reset token."""
    findings = doc.get("findings", [])
    has_weak_token = any(f.get("id") in _TOKEN_WEAKNESS_IDS for f in findings)
    weak_token_ids = sorted({f["id"] for f in findings if f.get("id") in _TOKEN_WEAKNESS_IDS})

    nodes = []
    for f in findings:
        if f.get("id") in _TOKEN_WEAKNESS_IDS:
            continue  # the token weakness itself is context, not a path node
        depth = _path_depth(f.get("url", ""))
        relevant_token_context = (
            has_weak_token and f.get("category") in _SESSION_RELEVANT_CATEGORIES
        )
        narrative = (
            f"{f.get('id')} at {f.get('url')} is reachable ~{depth} click(s) from the "
            f"target root (path-depth heuristic, not a real link-graph traversal)."
        )
        if relevant_token_context:
            narrative += (
                " This scan also found evidence of a guessable session/reset token "
                f"({', '.join(weak_token_ids)}) -- worth checking whether exploiting "
                "this finding is reachable via that weak token, not just via an "
                "already-authenticated session."
            )
        nodes.append(
            {
                "id": f.get("id"),
                "url": f.get("url"),
                "severity": f.get("severity"),
                "category": f.get("category"),
                "path_depth": depth,
                "relevant_token_context": relevant_token_context,
                "narrative": narrative,
            }
        )

    def _sort_key(n: dict) -> tuple:
        return (n["path_depth"], n["severity"] != "critical", n["severity"] != "high")

    nodes.sort(key=_sort_key)

    return {
        "target": doc.get("target", ""),
        "path_depth_is_heuristic": True,
        "weak_tokens_found": weak_token_ids,
        "nodes": nodes,
    }


def render_attack_path_markdown(report: dict) -> str:
    lines = [
        f"# Attack-path graph for {report.get('target', '')}",
        "",
        "Distances are a **path-depth heuristic** (URL segment count from the "
        "target root), not a real crawl-link-graph traversal -- treat as an "
        "approximation of click-distance, not a guarantee.",
        "",
    ]
    if report.get("weak_tokens_found"):
        lines.append(
            f"This scan found evidence of guessable session/reset tokens: "
            f"{', '.join(report['weak_tokens_found'])}."
        )
        lines.append("")
    for node in report.get("nodes", []):
        lines.append(f"## `{node['id']}` ({node['severity']}) @ `{node['url']}`")
        lines.append("")
        lines.append(node["narrative"])
        lines.append("")
    return "\n".join(lines)
