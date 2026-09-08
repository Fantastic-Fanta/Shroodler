"""APIs the HTML crawler never queues: JSON-RPC, tRPC, React Query, GraphQL ops.

Templates and method names only — this does not call the methods.
"""

from __future__ import annotations

import re

from shroodler.models import Finding, JsEndpoint

_JSONRPC_METHOD = re.compile(
    r"""["']jsonrpc["']\s*:.*?["']method["']\s*:\s*["']([A-Za-z_][\w./:]{1,80})["']""",
    re.S,
)
_JSONRPC_METHOD_ALT = re.compile(
    r"""["']method["']\s*:\s*["']([A-Za-z_][\w./:]{1,80})["']\s*,\s*["']jsonrpc["']"""
)
_TRPC = re.compile(
    r"""\.(?:query|mutation|subscription)\(\s*["']([A-Za-z_][\w./]{1,80})["']"""
)
_REACT_QUERY = re.compile(
    r"""(?:useQuery|useMutation|queryKey)\(\s*\[\s*["'](/(?:[^"'\\]|\\.){1,120})["']"""
)
_GQL_OP = re.compile(
    r"""\b(query|mutation|subscription)\s+([A-Za-z_][\w]{1,60})\s*[\({]"""
)
_GQL_TAG = re.compile(
    r"""\bgql\s*`[^`]{0,400}?\b(query|mutation|subscription)\s+([A-Za-z_][\w]{1,60})""",
    re.S,
)


def extract_js_api_surface(
    source_url: str, js_text: str
) -> tuple[list[JsEndpoint], list[Finding]]:
    endpoints: list[JsEndpoint] = []
    findings: list[Finding] = []
    if not js_text:
        return endpoints, findings
    seen: set[str] = set()

    def add(kind: str, name: str, finding_id: str, description: str) -> None:
        key = f"{kind}:{name}"
        if key in seen or not name:
            return
        seen.add(key)
        marker = f"{kind}:{name}"
        endpoints.append(JsEndpoint(source=source_url, endpoint=marker))
        findings.append(
            Finding(
                id=finding_id,
                severity="info",
                category="js-endpoint",
                url=source_url,
                description=description,
                evidence=name,
            )
        )

    for pat in (_JSONRPC_METHOD, _JSONRPC_METHOD_ALT):
        for match in pat.finditer(js_text):
            add(
                "jsonrpc",
                match.group(1),
                "js-jsonrpc-method",
                f"JS references JSON-RPC method {match.group(1)}",
            )
    for match in _TRPC.finditer(js_text):
        add(
            "trpc",
            match.group(1),
            "js-trpc-procedure",
            f"JS references tRPC procedure {match.group(1)}",
        )
    for match in _REACT_QUERY.finditer(js_text):
        add(
            "react-query",
            match.group(1),
            "js-react-query-key",
            f"JS React Query key names path {match.group(1)}",
        )
    for pat in (_GQL_TAG, _GQL_OP):
        for match in pat.finditer(js_text):
            op, name = match.group(1), match.group(2)
            add(
                f"graphql-{op}",
                name,
                "js-graphql-operation",
                f"JS references GraphQL {op} {name}",
            )
    return endpoints, findings


def crawl_seeds_from_endpoint(origin: str, marker: str) -> list[str]:
    """Turn tRPC / React Query markers into same-origin URLs the crawler can queue.

    JSON-RPC method names and GraphQL operation names are not URLs.
    """
    from shroodler.urls import normalize_url, same_origin

    if not origin or not marker:
        return []
    kind, _, rest = marker.partition(":")
    if not rest:
        return []
    if kind == "react-query":
        path = rest.strip()
        if not path.startswith("/") or path.startswith("//"):
            return []
        if ".." in path or any(ord(c) < 32 for c in path):
            return []
        joined = normalize_url(origin if origin.endswith("/") else origin + "/", path)
        if joined and same_origin(joined, origin):
            return [joined]
        return []
    if kind == "trpc":
        proc = rest.strip()
        if not proc or ".." in proc or "://" in proc or any(c in proc for c in " <>{}\\"):
            return []
        if any(ord(c) < 32 for c in proc):
            return []
        joined = normalize_url(
            origin if origin.endswith("/") else origin + "/",
            "/trpc/" + proc,
        )
        if joined and same_origin(joined, origin):
            return [joined]
        return []
    return []


def extract_endpoints(js_text: str) -> list[str]:
    """Raw endpoint strings (paths and absolute URLs) referenced in JS.

    Combines fetch/axios/XHR paths with React Query keys and tRPC procedures.
    """
    from shroodler.extractors.js_endpoints import extract_js_endpoints

    out: list[str] = []
    seen: set[str] = set()

    def add(raw: str) -> None:
        value = (raw or "").strip()
        if not value or value in seen:
            return
        seen.add(value)
        out.append(value)

    endpoints, _findings = extract_js_endpoints("", js_text or "")
    for ep in endpoints:
        add(ep.endpoint)
    markers, _ = extract_js_api_surface("", js_text or "")
    for marker in markers:
        kind, _, rest = marker.endpoint.partition(":")
        if kind == "react-query":
            add(rest)
        elif kind == "trpc":
            add("/trpc/" + rest)
    return out
