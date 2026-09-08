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
