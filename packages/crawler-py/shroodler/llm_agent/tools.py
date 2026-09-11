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
        "name": "send_request",
        "description": (
            "Craft and send ANY HTTP request, then read the result: status, "
            "timing, where your input reflected, and a body snippet. Use this "
            "to write your own payloads and reason about the response instead "
            "of relying on the fixed probes."
        ),
        "params": {
            "url": "str",
            "method": "GET|POST|PUT|DELETE|... (default GET)",
            "headers": "dict | null",
            "params": "dict | null — query (GET) or form fields (else)",
            "body": "str | dict | null — raw or JSON body",
            "include_auth": "bool — send the owner session (default true)",
        },
    },
    {
        "name": "compare_responses",
        "description": (
            "Send two requests (a and b) and diff them. Use to test tampering: "
            "e.g. a=normal price, b=altered price; or a param present vs removed."
        ),
        "params": {
            "a": "dict — {url, method, params, body, headers, include_auth}",
            "b": "dict — same shape as a",
        },
    },
    {
        "name": "replay_as_user",
        "description": (
            "Send the same request as the owner, a lower-privilege peer, and "
            "anonymously; compare the three. Use for broken access control: if "
            "peer or anon get the owner's data, that's a lead."
        ),
        "params": {"url": "str", "method": "GET|POST", "params": "dict | null"},
    },
    {
        "name": "decode_token",
        "description": (
            "Decode a JWT (header+payload, no verification) or base64 blob and "
            "flag weak signals like alg:none or HMAC. No network request."
        ),
        "params": {"token": "str"},
    },
    {
        "name": "craft_payloads",
        "description": (
            "Ask the model to write payloads tailored to what you've already "
            "observed (DB, template engine, framework, reflection context), fire "
            "them at a parameter, and report which produced a signal. Pass the "
            "evidence you saw so the payloads are specific, not generic."
        ),
        "params": {
            "url": "str",
            "param": "str — parameter to inject (empty targets the URL/body)",
            "vuln_class": "str — e.g. sqli, xss, ssti, path_traversal",
            "method": "GET|POST",
            "evidence": "str — response text/errors/stack you already observed",
        },
    },
    {
        "name": "verify_finding",
        "description": (
            "Re-fetch a finding's URL and judge, from fresh evidence, whether it "
            "is real. Confirms it, adjusts its confidence, or removes it as a "
            "false positive. Call this on tentative findings before reporting."
        ),
        "params": {"finding_id": "str", "url": "str | null"},
    },
    {
        "name": "analyze_logic",
        "description": (
            "Reason about business-logic and authorization abuse from the "
            "crawled workflow (price tampering, coupon reuse, step-skipping, "
            "negative quantities, IDOR chains) and queue hypotheses to test. "
            "Use when signature probes are exhausted or the app has a clear flow."
        ),
        "params": {},
    },
    {
        "name": "test_hypothesis",
        "description": (
            "Pop the top pending hypothesis (from hypothesise/analyze_logic), "
            "translate it into one concrete in-scope test, run it, and record "
            "whether it validated. Use this to actually chase the ideas in the "
            "PENDING HYPOTHESES list instead of leaving them untested."
        ),
        "params": {"index": "int | null — specific hypothesis, or null for the next pending"},
    },
    {
        "name": "hypothesise",
        "description": (
            "Record a hypothesis about a potential vulnerability to investigate. "
            "Does not make any requests — just notes what to try next. Use "
            "test_hypothesis later to actually check it."
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
