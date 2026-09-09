"""Tool manifest for the opt-in Claude agent loop."""

from __future__ import annotations

from typing import Any

TOOLS: list[dict[str, Any]] = [
    {
        "name": "crawl",
        "description": (
            "Crawl a URL or the whole target to discover pages, endpoints, "
            "and parameters. Use when you need to explore new surface area."
        ),
        "params": {
            "url": "str | None — specific URL to crawl, or null for full target crawl"
        },
    },
    {
        "name": "probe_sqli",
        "description": (
            "Test a URL parameter for SQL injection "
            "(error-based, time-based, boolean-based)."
        ),
        "params": {"url": "str", "param": "str", "method": "GET|POST"},
    },
    {
        "name": "probe_xss",
        "description": "Test a URL parameter for reflected and stored XSS.",
        "params": {"url": "str", "param": "str", "method": "GET|POST"},
    },
    {
        "name": "probe_idor",
        "description": "Test a numeric ID parameter for IDOR by probing neighbour IDs.",
        "params": {"url": "str", "param": "str", "current_value": "str"},
    },
    {
        "name": "probe_ssrf",
        "description": "Test a URL-like parameter for SSRF.",
        "params": {"url": "str", "param": "str"},
    },
    {
        "name": "probe_open_redirect",
        "description": "Test a redirect parameter for open redirect.",
        "params": {"url": "str", "param": "str"},
    },
    {
        "name": "probe_path_traversal",
        "description": "Test a file path parameter for directory traversal.",
        "params": {"url": "str", "param": "str"},
    },
    {
        "name": "probe_ssti",
        "description": "Test a string parameter for server-side template injection.",
        "params": {"url": "str", "param": "str"},
    },
    {
        "name": "probe_host_header",
        "description": "Test an endpoint for host header injection.",
        "params": {"url": "str"},
    },
    {
        "name": "probe_jwt",
        "description": (
            "Test JWT tokens found in cookies/headers for weak secrets, "
            "alg:none, algorithm confusion."
        ),
        "params": {"url": "str"},
    },
    {
        "name": "probe_graphql",
        "description": "Test a GraphQL endpoint for introspection, injection, and IDOR.",
        "params": {"url": "str"},
    },
    {
        "name": "check_authz",
        "description": (
            "Replay a URL as a lower-privilege or anonymous session to check "
            "for broken access control."
        ),
        "params": {"url": "str"},
    },
    {
        "name": "fetch_and_read",
        "description": (
            "Fetch a URL and return its response body for analysis. Use when "
            "you want to understand what an endpoint returns before probing it."
        ),
        "params": {
            "url": "str",
            "method": "GET|POST",
            "params": "dict | null",
        },
    },
    {
        "name": "hypothesise",
        "description": (
            "Record a hypothesis about a potential vulnerability to investigate. "
            "Does not make any requests — just notes what to try next."
        ),
        "params": {"hypothesis": "str", "target_url": "str", "reasoning": "str"},
    },
    {
        "name": "report",
        "description": (
            "Generate the final report and end the engagement. Use when you have "
            "exhausted the interesting attack surface or reached the iteration budget."
        ),
        "params": {},
    },
]


def tool_by_name(name: str) -> dict[str, Any] | None:
    """Return the tool dict for `name`, or None if unknown."""
    wanted = str(name or "").strip()
    if not wanted:
        return None
    for tool in TOOLS:
        if tool.get("name") == wanted:
            return tool
    return None
