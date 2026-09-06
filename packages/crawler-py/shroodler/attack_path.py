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

import re
from urllib.parse import unquote, urlparse

_TOKEN_WEAKNESS_IDS = {
    "reset-token-sequential",
    "reset-token-small-keyspace",
    "reset-token-short",
    "reset-token-in-url",
}

# Findings whose exploitation plausibly involves session/account context,
# so a same-scan weak-token finding is worth flagging alongside them.
_SESSION_RELEVANT_CATEGORIES = {"auth"}

# Top-level path segments too generic to mean anything on their own --
# virtually every route on a REST API/SPA backend lives under one of
# these (/api/v1/reset-password and /api/v1/account/settings share top-
# level segment "api"), so matching on it alone reintroduces "any weak
# token anywhere correlates with any auth finding anywhere" on any site
# organized this way. A literal denylist can't enumerate every naming
# scheme -- that's an accepted limitation of a best-effort heuristic,
# and a missed correlation here is a much cheaper failure than the
# scan-wide-noise flood this list exists to prevent -- but a VERSION
# segment specifically is common and pattern-matchable ("v4", "v12",
# or a bare numeral like a Twitter-style "/2/tweets"), so that case is
# covered by pattern instead of needing every version number enumerated.
_GENERIC_TOP_SEGMENTS = {
    "api",
    "app",
    "rest",
    "service",
    "services",
    "graphql",
    "internal",
    "gateway",
    "backend",
    "platform",
}
_VERSION_SEGMENT_RE = re.compile(r"^v?\d+(\.\d+)*$", re.IGNORECASE)


def _is_generic_segment(segment: str) -> bool:
    return segment.lower() in _GENERIC_TOP_SEGMENTS or bool(_VERSION_SEGMENT_RE.match(segment))


def _path_depth(url: str) -> int:
    # Decode percent-encoding before counting segments -- otherwise a
    # genuinely deep path written as /a%2Fb%2Fc%2Fcritical (a real,
    # browser-decoded 4-segment path) counts as depth 1, sorting a
    # critical finding at an obscure, deeply-nested route to the TOP of
    # the report as if it were the shallowest/most-exposed one, actively
    # misleading a reader who trusts the "closer to root = higher
    # priority to check" framing this report otherwise takes pains to
    # present honestly.
    path = unquote(urlparse(url).path or "/")
    return len([s for s in path.split("/") if s])


def _path_segments(url: str) -> tuple[str, ...]:
    path = unquote(urlparse(url).path or "/")
    return tuple(s for s in path.split("/") if s)


def _strip_generic_prefix(segments: tuple[str, ...]) -> tuple[str, ...]:
    """Drop leading segments too generic to identify a subsystem on
    their own (api, v1, v2, app, ...) -- a path can stack more than one
    (/api/v1/reset-password has two), so this strips ALL of them, not
    just the first."""
    i = 0
    while i < len(segments) and _is_generic_segment(segments[i]):
        i += 1
    return segments[i:]


def _same_subsystem(url_a: str, url_b: str) -> bool:
    """True when two URLs plausibly belong to the same subsystem: the
    same leading path segment ONCE any purely structural/generic prefix
    segments (api, v1, app, ...) are stripped from both -- a shared
    "api" or "api/v1" prefix alone is not enough to correlate an
    otherwise-unrelated weak-token finding with an otherwise-unrelated
    auth finding, since virtually every route on a typical REST API/SPA
    backend shares it.
    """
    segs_a = _strip_generic_prefix(_path_segments(url_a))
    segs_b = _strip_generic_prefix(_path_segments(url_b))
    return bool(segs_a) and bool(segs_b) and segs_a[0] == segs_b[0]


def build_attack_path(doc: dict) -> dict:
    """Returns a report correlating every finding in `doc` with its
    path-depth (reachability proxy) and whether the same scan found
    evidence of a guessable session/reset token."""
    findings = doc.get("findings", [])
    weak_token_findings = [f for f in findings if f.get("id") in _TOKEN_WEAKNESS_IDS]
    weak_token_ids = sorted({f["id"] for f in weak_token_findings})
    weak_token_urls = [f.get("url", "") for f in weak_token_findings]

    nodes = []
    for f in findings:
        if f.get("id") in _TOKEN_WEAKNESS_IDS:
            continue  # the token weakness itself is context, not a path node
        depth = _path_depth(f.get("url", ""))
        # Scoped to the same subsystem as at least one weak-token
        # finding (see _same_subsystem), not "flag every auth-category
        # finding in the whole scan off any weak token anywhere" -- an
        # earlier version did the latter, which on a large multi-
        # subsystem site repeats the identical boilerplate sentence on
        # every unrelated auth finding, training readers to ignore it.
        relevant_token_context = f.get("category") in _SESSION_RELEVANT_CATEGORIES and any(
            _same_subsystem(f.get("url", ""), token_url) for token_url in weak_token_urls
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
