"""Tool implementations exposed over MCP.

Each function takes a plain dict of arguments and returns a plain,
JSON-serializable dict. Kept free of any protocol/transport concerns so
they're independently unit-testable and reusable from a plain Python
REPL, not just an agent. `server.py` validates `arguments` against each
tool's `input_schema` before calling the handler; handlers still validate
domain-level requirements (e.g. "one of A or B must be set") themselves.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from shroodler_mcp.paths import ensure_on_path, payload_tester_dir, report_generator_dir


# An MCP client -- or a coding agent whose context was poisoned by
# adversarial content it read elsewhere in the same session -- can supply
# any string for a "path to a file on disk" argument. Restricting reads to
# a project root bounds that to "files this project could plausibly want
# the tool to read" instead of "any file this OS user can read".
#
# The process's bare working directory is NOT used as that root: many MCP
# hosts launch a stdio server with an unspecified or ambient cwd (e.g. the
# user's home directory), and anchoring there would happily permit
# reading ~/.ssh/id_rsa or ~/.aws/credentials -- narrower than "any file"
# but still far more than intended. Instead: an explicit
# SHROODLER_MCP_ROOT wins if set; otherwise walk up from cwd looking for
# a `.git` directory (the same "find the project root" heuristic as
# everything else in this repo) and use that; only if neither exists does
# this fall back to bare cwd, which is then just as good/bad as the
# process's launch directory -- operators who care should set
# SHROODLER_MCP_ROOT. Set SHROODLER_MCP_ALLOW_ANY_PATH=1 to disable
# sandboxing entirely for a trusted, operator-controlled setup.
def _project_root() -> Path:
    env = os.environ.get("SHROODLER_MCP_ROOT")
    if env:
        return Path(env).expanduser().resolve()
    cwd = Path.cwd().resolve()
    for candidate in (cwd, *cwd.parents):
        if (candidate / ".git").exists():
            return candidate
    return cwd


def _resolve_safe_path(raw: str) -> Path:
    resolved = Path(raw).expanduser().resolve()
    if os.environ.get("SHROODLER_MCP_ALLOW_ANY_PATH") == "1":
        return resolved
    root = _project_root()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(
            f"refusing to read {raw!r}: outside the project root {root} "
            "(set SHROODLER_MCP_ROOT to change it, or SHROODLER_MCP_ALLOW_ANY_PATH=1 "
            "to allow arbitrary paths)"
        ) from exc
    return resolved


def _build_enforcer(args: dict, target: str):
    """Shared by every tool that fires live requests at a target
    (scan_route's payload run, check_idor's replay): refuse to proceed
    unless the target publishes a scan-policy consent manifest, unless
    the caller explicitly opts out via `allow_without_policy`. This is
    the one guardrail an MCP client/agent can't skip by just not passing
    a CLI flag the way a human running `shroodler payload` without
    `--require-policy` implicitly can.
    """
    from shroodler_guardrails.policy import (
        PolicyEnforcer,
        PolicyViolation,
        fetch_policy,
        origin_of,
        parse_policy,
    )

    policy_file = args.get("policy_file")
    require_policy = not bool(args.get("allow_without_policy", False))
    if policy_file:
        manifest = json.loads(_resolve_safe_path(policy_file).read_text(encoding="utf-8"))
        policy = parse_policy(manifest, origin=origin_of(target))
    else:
        policy = fetch_policy(target)
    try:
        return PolicyEnforcer(
            policy=policy,
            require_policy=require_policy,
            audit_path=_resolve_safe_path(args["audit_log"]) if args.get("audit_log") else None,
        )
    except PolicyViolation as exc:
        raise ValueError(str(exc)) from exc


def _load_doc(value: Any) -> dict:
    """Accept either an inline crawl-document object or a path to one on
    disk -- an agent that just ran a crawl in-session has the dict in
    hand and shouldn't have to round-trip it through a temp file just to
    call another tool."""
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        return json.loads(_resolve_safe_path(value).read_text(encoding="utf-8"))
    raise ValueError("expected a crawl-document object or a path to one")


def scan_route(args: dict) -> dict:
    """Crawl exactly one URL (no link-following) and optionally run active
    payload packs against what it finds. This is the "agent wants to check
    the route it's about to commit, mid-session" tool -- a single-page
    scan is fast enough to run inline before a commit rather than waiting
    for a full site crawl.

    When `run_payloads` is set, active requests are gated by
    `shroodler_guardrails.policy.PolicyEnforcer` the same way `shroodler
    payload --require-policy` is: by default a target must publish a
    `.well-known/scan-policy.json` consent manifest before this tool will
    fire live payloads at it, since this is the one code path an agent can
    trigger autonomously without a human typing a CLI flag. Pass
    `allow_without_policy: true` to explicitly opt out for a target that
    hasn't deployed a manifest yet (e.g. local dev).
    """
    from shroodler.crawler import crawl_url
    from shroodler.validate import validate_crawl

    url = args.get("url")
    if not url:
        raise ValueError("scan_route requires 'url'")
    allow_external = bool(args.get("allow_external", False))
    run_payloads = bool(args.get("run_payloads", False))

    result = crawl_url(
        url,
        mode=args.get("mode", "static"),
        depth=0,
        max_pages=1,
        allow_external=allow_external,
        cookies=list(args.get("cookies") or []),
        headers=list(args.get("headers") or []),
    )
    doc = result.to_dict()
    validate_crawl(doc)

    if run_payloads:
        ensure_on_path(payload_tester_dir())
        import tester

        enforcer = _build_enforcer(args, doc.get("target", ""))
        payload_out = tester.run(doc, allow_external=allow_external, enforcer=enforcer)
        doc["findings"] = list(doc.get("findings", [])) + payload_out["findings"]
        doc["oob_probes"] = payload_out.get("oob_probes", [])
        doc["guardrail"] = payload_out.get("guardrail")

    return doc


def check_idor(args: dict) -> dict:
    """Confirm/refute a suspected IDOR by replaying a privileged crawl's
    URLs under a second, lower-privileged session -- wraps `authz-diff`,
    the mechanism the roadmap's "agent-driven lead confirmation" idea
    reuses: a documented single-session limitation becomes something an
    agent can resolve by spinning up a second session and calling this.

    Like `scan_route`'s payload run, this fires real requests at the
    target and is gated by the same scan-policy consent manifest by
    default (`allow_without_policy: true` to opt out) -- this is the
    other autonomously-triggerable active-testing tool on this surface,
    and it doesn't get a free pass just because its requests are GETs
    rather than payload sends.
    """
    from shroodler.authz_diff import run as authz_diff_run

    higher_doc = _load_doc(args.get("higher_priv_crawl"))
    if not higher_doc:
        raise ValueError("check_idor requires 'higher_priv_crawl' (doc or path)")
    enforcer = _build_enforcer(args, higher_doc.get("target", ""))
    return authz_diff_run(
        higher_doc,
        cookie_header=args.get("lower_priv_cookie", ""),
        check_anonymous=bool(args.get("check_anonymous", True)),
        allow_external=bool(args.get("allow_external", False)),
        enforcer=enforcer,
    )


def diff_since_baseline(args: dict) -> dict:
    """Compare a fresh scan against a checked-in baseline and return what
    changed -- the "what's new since Tuesday's deploy" question, without
    the agent having to shell out to the CLI and parse text output."""
    from shroodler.diffcmd import diff_outcome
    from shroodler.suppress import load_suppressions

    actual = _load_doc(args.get("crawl"))
    expected = _load_doc(args.get("baseline"))
    suppressions = []
    if args.get("suppressions_file"):
        suppressions = load_suppressions(_resolve_safe_path(args["suppressions_file"]))
    outcome = diff_outcome(
        actual,
        expected,
        gate=bool(args.get("gate", True)),
        suppressions=suppressions,
    )
    return {"errors": outcome.errors, "resolved": outcome.resolved, "clean": not outcome.errors}


def explain_finding(args: dict) -> dict:
    """Static remediation guidance for a finding id/category -- lets an
    agent ask "what do I do about this" without a human opening the docs."""
    ensure_on_path(report_generator_dir())
    from remediation import remediation_for

    finding_id = args.get("finding_id", "")
    category = args.get("category", "")
    if not finding_id and not category:
        raise ValueError("explain_finding requires 'finding_id' and/or 'category'")
    return {
        "finding_id": finding_id,
        "category": category,
        "remediation": remediation_for(finding_id, category),
    }


TOOLS: dict[str, dict[str, Any]] = {
    "scan_route": {
        "description": "Crawl a single route/URL (no link-following) for passive findings, "
        "optionally running active payload packs against it. Use before committing a "
        "change to a specific route. Active payloads are refused unless the target "
        "publishes a scan-policy consent manifest, or allow_without_policy is set.",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "url": {"type": "string", "description": "The route/URL to scan"},
                "mode": {"type": "string", "enum": ["static", "headless"], "default": "static"},
                "run_payloads": {
                    "type": "boolean",
                    "default": False,
                    "description": "Also run active payload packs (SQLi/XSS/SSTI/etc.) against this route",
                },
                "allow_without_policy": {
                    "type": "boolean",
                    "default": False,
                    "description": "Allow active payloads even without a scan-policy manifest "
                    "(only for targets you already know you're authorized to test)",
                },
                "policy_file": {
                    "type": "string",
                    "description": "Local scan-policy.json path instead of fetching one from the target",
                },
                "audit_log": {"type": "string", "description": "Path to append a JSONL audit trail to"},
                "allow_external": {"type": "boolean", "default": False},
                "cookies": {"type": "array", "items": {"type": "string"}},
                "headers": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["url"],
        },
        "handler": scan_route,
    },
    "check_idor": {
        "description": "Replay a privileged crawl's URLs under a second, lower-privileged "
        "session's cookie to confirm or drop a suspected IDOR/broken-access-control lead. "
        "Requires the target to publish a scan-policy consent manifest unless "
        "allow_without_policy is set.",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "higher_priv_crawl": {
                    "description": "Crawl-document object, or a path to one on disk, "
                    "produced under the higher-privileged session",
                },
                "lower_priv_cookie": {
                    "type": "string",
                    "description": "Cookie header value for the lower-privileged session",
                },
                "check_anonymous": {"type": "boolean", "default": True},
                "allow_external": {"type": "boolean", "default": False},
                "allow_without_policy": {"type": "boolean", "default": False},
                "policy_file": {"type": "string"},
                "audit_log": {"type": "string"},
            },
            "required": ["higher_priv_crawl"],
        },
        "handler": check_idor,
    },
    "diff_since_baseline": {
        "description": "Compare a fresh scan against a checked-in expected-findings baseline "
        "and report what's new, resolved, or unexpectedly missing.",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "crawl": {"description": "Crawl-document object, or a path to one on disk"},
                "baseline": {"description": "Baseline object, or a path to one on disk"},
                "gate": {"type": "boolean", "default": True},
                "suppressions_file": {"type": "string"},
            },
            "required": ["crawl", "baseline"],
        },
        "handler": diff_since_baseline,
    },
    "explain_finding": {
        "description": "Get static remediation guidance for a finding id or category.",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "finding_id": {"type": "string"},
                "category": {"type": "string"},
            },
        },
        "handler": explain_finding,
    },
}
