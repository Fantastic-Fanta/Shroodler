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

1. Click distance is a walk of the links the crawl recorded (`edges`:
   from-url, to-url, and kind). An HTML link or a form action counts as
   one click. A redirect counts as zero: the browser follows it without
   another click. When the crawl JSON has no edges (files written before
   crawlers stored them), distance falls back to URL path depth (segment
   count) and every rendered sentence says so. A finding whose URL is
   not reachable from the start URL through those edges uses that same
   path-depth fallback and says so, even when other findings used the
   graph.
2. "Needs a session token this scan proved guessable" is a same-scan
   correlation, not a proof that a specific finding's exploitation path
   actually routes through that specific token -- it means the scan
   found evidence of at least one weak token AND at least one finding
   whose category suggests session/account context, and surfaces that
   as a hypothesis worth investigating, not a confirmed chain.
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from urllib.parse import unquote, urlparse

from shroodler.urls import canonical_key

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


def _click_distances(target: str, edges: list) -> dict[str, int]:
    """Shortest click distance from the start URL. Redirects weigh 0."""
    start = canonical_key(target) if target else ""
    adj: dict[str, list[tuple[str, int]]] = defaultdict(list)
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        frm = canonical_key(str(edge.get("from_url") or ""))
        to = canonical_key(str(edge.get("to_url") or ""))
        if not frm or not to:
            continue
        weight = 0 if edge.get("kind") == "redirect" else 1
        adj[frm].append((to, weight))
    dist: dict[str, int] = {}
    if not start:
        return dist
    dist[start] = 0
    pending: deque[str] = deque([start])
    while pending:
        current = pending.popleft()
        for nxt, weight in adj.get(current, []):
            candidate = dist[current] + weight
            if nxt in dist and candidate >= dist[nxt]:
                continue
            dist[nxt] = candidate
            if weight == 0:
                pending.appendleft(nxt)
            else:
                pending.append(nxt)
    return dist


def build_attack_path(doc: dict) -> dict:
    """Returns a report correlating every finding in `doc` with how many
    clicks it is from the start URL, and whether the same scan found
    evidence of a guessable session/reset token.

    Crawls that recorded edges use those links. Crawls with no edges
    keep the path-depth (slash-count) heuristic and say so.
    """
    findings = doc.get("findings", [])
    raw_edges = doc.get("edges") or []
    use_edges = isinstance(raw_edges, list) and len(raw_edges) > 0
    distances = _click_distances(doc.get("target") or "", raw_edges) if use_edges else {}
    weak_token_findings = [f for f in findings if f.get("id") in _TOKEN_WEAKNESS_IDS]
    weak_token_ids = sorted({f["id"] for f in weak_token_findings})
    weak_token_urls = [f.get("url", "") for f in weak_token_findings]

    nodes = []
    for f in findings:
        if f.get("id") in _TOKEN_WEAKNESS_IDS:
            continue  # the token weakness itself is context, not a path node
        url = f.get("url", "")
        depth = _path_depth(url)
        on_graph = use_edges and canonical_key(url) in distances
        distance = distances[canonical_key(url)] if on_graph else depth
        if on_graph:
            narrative = (
                f"{f.get('id')} at {f.get('url')} is {distance} click(s) from the "
                "start URL (links this crawl followed; a redirect is not a click)."
            )
        elif use_edges:
            narrative = (
                f"{f.get('id')} at {f.get('url')} is reachable ~{depth} click(s) from the "
                "target root (path-depth heuristic: this URL is not on a followed "
                "link from the start URL)."
            )
        else:
            narrative = (
                f"{f.get('id')} at {f.get('url')} is reachable ~{depth} click(s) from the "
                "target root (path-depth heuristic, not a real link-graph traversal)."
            )
        # Scoped to the same subsystem as at least one weak-token
        # finding (see _same_subsystem), not "flag every auth-category
        # finding in the whole scan off any weak token anywhere" -- an
        # earlier version did the latter, which on a large multi-
        # subsystem site repeats the identical boilerplate sentence on
        # every unrelated auth finding, training readers to ignore it.
        relevant_token_context = f.get("category") in _SESSION_RELEVANT_CATEGORIES and any(
            _same_subsystem(f.get("url", ""), token_url) for token_url in weak_token_urls
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
                "click_distance": distance,
                "distance_is_heuristic": not on_graph,
                "relevant_token_context": relevant_token_context,
                "narrative": narrative,
            }
        )

    def _sort_key(n: dict) -> tuple:
        return (n["click_distance"], n["severity"] != "critical", n["severity"] != "high")

    nodes.sort(key=_sort_key)

    return {
        "target": doc.get("target", ""),
        "path_depth_is_heuristic": not use_edges,
        "weak_tokens_found": weak_token_ids,
        "nodes": nodes,
    }


def render_attack_path_markdown(report: dict) -> str:
    if report.get("path_depth_is_heuristic"):
        disclaimer = (
            "Distances are a **path-depth heuristic** (URL segment count from the "
            "target root), not a real crawl-link-graph traversal -- treat as an "
            "approximation of click-distance, not a guarantee. This crawl did not "
            "record the links it followed."
        )
    else:
        disclaimer = (
            "Distances are click counts along links this crawl followed "
            "(an HTML link or a form action is one click; a redirect is not a click). "
            "A URL that is not on any followed path still uses the path-depth "
            "heuristic, and that node's sentence says so."
        )
    lines = [
        f"# Attack-path graph for {report.get('target', '')}",
        "",
        disclaimer,
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
