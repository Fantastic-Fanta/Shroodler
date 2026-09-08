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
    (scan_route's payload run, check_idor's replay, peer_write, paced_fetch): refuse to proceed
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

    When `run_payloads` is set, OR `mode` is "headless", a scan-policy
    consent manifest is required by default (`allow_without_policy: true`
    to opt out), the same way `shroodler payload --require-policy` works.
    "static" mode is a passive GET -- but headless mode drives real
    Chromium and clicks into buttons/links to enumerate SPA routes (see
    `shroodler/modes/headless.py`'s `_enumerate_routes`), which can fire
    real state-changing requests (a "confirm purchase" button, a logout,
    an admin action) with no payload ever sent. Treating headless mode as
    "just a passive crawl" would let an agent cause real side effects on
    an unconsented target through this tool with default arguments, so it
    gets the same manifest requirement as active payload sends. Note this
    gates the manifest CHECK at the route level (refuses to even start a
    headless crawl of an unconsented target), not each individual click
    headless mode makes internally -- per-click scope enforcement inside
    the Playwright click loop is a known follow-up, not yet implemented.
    """
    from shroodler.crawler import crawl_url
    from shroodler.validate import validate_crawl

    url = args.get("url")
    if not url:
        raise ValueError("scan_route requires 'url'")
    allow_external = bool(args.get("allow_external", False))
    run_payloads = bool(args.get("run_payloads", False))
    mode = args.get("mode", "static")

    enforcer = None
    if run_payloads or mode == "headless":
        enforcer = _build_enforcer(args, url)

    result = crawl_url(
        url,
        mode=mode,
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

    Pass `higher_priv_identity_markers` (strings only the higher-priv
    account's own data should contain -- an email, username, or record
    value) so a lead where the lower-priv response actually contains one
    is upgraded to confidence="confirmed" instead of just "reachable";
    an agent that already knows both test accounts' identities can
    supply these directly. `require_identity_confirmation: true` drops
    an unconfirmed lead instead of reporting it.
    """
    from shroodler.authz_diff import run as authz_diff_run

    higher_doc = _load_doc(args.get("higher_priv_crawl"))
    if not higher_doc:
        raise ValueError("check_idor requires 'higher_priv_crawl' (doc or path)")
    enforcer = _build_enforcer(args, higher_doc.get("target", ""))
    gql_names = list(args.get("gql_field_names") or [])
    paths: list[Path] = []
    if args.get("gql_schema"):
        paths.append(_resolve_safe_path(args["gql_schema"]))
    if args.get("gql_wordlist"):
        paths.append(_resolve_safe_path(args["gql_wordlist"]))
    if paths:
        from shroodler.extractors.graphql import load_graphql_field_names

        gql_names.extend(load_graphql_field_names(paths))
    return authz_diff_run(
        higher_doc,
        cookie_header=args.get("lower_priv_cookie", ""),
        check_anonymous=bool(args.get("check_anonymous", True)),
        allow_external=bool(args.get("allow_external", False)),
        enforcer=enforcer,
        higher_priv_identity_markers=list(args.get("higher_priv_identity_markers") or []),
        lower_priv_identity_markers=list(args.get("lower_priv_identity_markers") or []),
        require_identity_confirmation=bool(args.get("require_identity_confirmation", False)),
        gql_field_names=gql_names,
    )


def reverify_fix(args: dict) -> dict:
    """Closed-loop remediate-and-reverify: after an agent (or human)
    patches source in response to a finding, call this on the same URL
    before opening/merging a PR. Only `verified_fixed: true` means the
    specific finding_id is actually gone from a FRESH re-scan of that
    route -- not merely "a patch was applied" or "the page still
    loads". Active payload re-runs (default on; set run_payloads=false
    to skip) are gated by the same scan-policy consent requirement as
    scan_route, for the same reason: this is a live-request-issuing
    tool an agent can trigger autonomously.

    IMPORTANT: the result also carries a `warnings` list (e.g. "url has
    no query string" when the URL you passed can't let the active
    re-run rediscover a GET parameter the original finding depended on)
    -- check it before treating `verified_fixed: true` as fully trusted;
    a non-empty list means this specific check may not have actually
    re-tested what the original finding was about. Also note: this tool
    only checks and reports; it does not generate a regression test file
    (that's a separate, CLI-only step -- `shroodler gen-regression-test`
    -- not currently exposed over MCP).
    """
    from shroodler.reverify import reverify

    url = args.get("url")
    finding_id = args.get("finding_id")
    if not url or not finding_id:
        raise ValueError("reverify_fix requires 'url' and 'finding_id'")
    run_payloads = bool(args.get("run_payloads", True))
    enforcer = _build_enforcer(args, url) if run_payloads else None
    return reverify(
        url,
        finding_id,
        mode=args.get("mode", "static"),
        allow_external=bool(args.get("allow_external", False)),
        run_payloads=run_payloads,
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


def peer_write(args: dict) -> dict:
    """Replay known-object writes as a peer session. Not n±1 enumeration.

    Requires a scan-policy consent manifest unless allow_without_policy is
    set. A 200 that matches the nonsense-id control is dummy-success, not
    a finding. Does not solve captchas.
    """
    from shroodler.peer_write import load_playbook
    from shroodler.peer_write import run as peer_write_run

    playbook: dict[str, Any] = {}
    if args.get("playbook") is not None:
        playbook = _load_doc(args.get("playbook"))
    sessions_path = None
    if args.get("from_sessions"):
        sessions_path = str(_resolve_safe_path(str(args["from_sessions"])))
    if not playbook and not sessions_path:
        raise ValueError("peer_write requires 'playbook' or 'from_sessions'")
    if args.get("target"):
        playbook["target"] = args["target"]
    merged = load_playbook(
        playbook,
        sessions_path=sessions_path,
        target=str(playbook.get("target") or args.get("target") or ""),
        only_id=args.get("only_id"),
    )
    target = str(merged.get("target") or "")
    if not target:
        raise ValueError("peer_write needs a target (playbook.target or target)")
    enforcer = _build_enforcer(args, target)
    return peer_write_run(
        merged,
        owner_cookie=str(args.get("owner_cookie") or ""),
        peer_cookie=str(args.get("peer_cookie") or ""),
        allow_external=bool(args.get("allow_external", False)),
        enforcer=enforcer,
        rate=float(args.get("rate") or 1.0),
        user_agent_suffix=str(args.get("user_agent_suffix") or ""),
        nonsense_id=str(args.get("nonsense_id") or "1"),
        only_id=args.get("only_id"),
        csrf=not bool(args.get("no_csrf", False)),
        csrf_from=str(args.get("csrf_from") or ""),
        require_confirm=(
            bool(args.get("require_confirm", False))
            or (
                bool(args.get("owner_cookie"))
                and bool(args.get("peer_cookie"))
                and not bool(args.get("allow_unconfirmed", False))
            )
        ),
        allow_unconfirmed=bool(args.get("allow_unconfirmed", False)),
    )


def session_export(args: dict) -> dict:
    """Convert a captured jar or CDP browser into Playwright storageState JSON."""
    from shroodler.session_export import export_session, origin_host

    origin = str(args.get("origin") or "")
    if not origin:
        raise ValueError("session_export requires origin (absolute http(s) URL)")
    origin_host(origin)
    source = args.get("from")
    path = str(_resolve_safe_path(str(source))) if source else None
    pairs = [str(args["cookie"])] if args.get("cookie") else None
    cdp = args.get("cdp")
    if cdp or source:
        # Do not GET origin/.well-known/scan-policy.json from this tool (SSRF).
        # A local policy_file is parsed; otherwise the operator must opt out.
        if args.get("policy_file"):
            _build_enforcer(args, origin)
        elif not args.get("allow_without_policy"):
            raise ValueError(
                "session_export with cdp or from requires policy_file or "
                "allow_without_policy (refusing to fetch scan-policy from origin)"
            )
    return export_session(
        source=path,
        cdp=cdp,
        origin=origin,
        pairs=pairs,
        allow_external=bool(args.get("allow_external", False)),
    )


def extract_js_routes(args: dict) -> dict:
    """Mine {userId}/{pk}/:id URL templates from a local JS file. File only."""
    from shroodler.extractors.js_routes import extract_js_routes_file

    raw = args.get("file")
    if not raw:
        raise ValueError("extract_js_routes requires 'file'")
    return extract_js_routes_file(_resolve_safe_path(str(raw)))


def paced_fetch(args: dict) -> dict:
    """GET a short URL list at a capped rate (default 1 req/s). Cap 20.

    Same scan-policy gate as check_idor. GET/HEAD/OPTIONS only. Does not
    solve captchas.
    """
    from shroodler.paced_fetch import MCP_MAX_URLS, fetch_urls

    urls = list(args.get("urls") or [])
    if args.get("url"):
        urls.append(str(args["url"]))
    urls = [u for u in (str(u).strip() for u in urls) if u]
    if not urls:
        raise ValueError("paced_fetch requires 'urls' or 'url'")
    target = urls[0]
    enforcer = _build_enforcer(args, target)
    return fetch_urls(
        urls,
        method=str(args.get("method") or "GET"),
        cookie_header=str(args.get("cookie") or ""),
        allow_external=bool(args.get("allow_external", False)),
        enforcer=enforcer,
        rate=float(args.get("rate") or 1.0),
        user_agent_suffix=str(args.get("user_agent_suffix") or ""),
        max_urls=MCP_MAX_URLS,
    )


def check_ws_idor(args: dict) -> dict:
    """Test whether a WebSocket server enforces per-user subscription authorization.

    Connects with the provided credentials, sends handshake_messages to establish
    a session, then tests own_subscriptions (baseline -- expected allowed) and
    victim_subscriptions (the IDOR probe -- should be denied). Responses are
    collected for `collect_seconds` after all messages are sent, then each
    subscription is classified by matching its sub_id in allow_pattern /
    deny_pattern against the collected raw text.

    Designed for Lightstreamer TLCP (SUBOK/REQERR) but configurable for any
    text-framed WS protocol via allow_pattern / deny_pattern.
    """
    import asyncio
    import re as _re
    import ssl

    ws_url = args.get("ws_url")
    if not ws_url:
        raise ValueError("check_ws_idor requires 'ws_url'")

    ws_protocol = args.get("ws_protocol")
    handshake_messages = list(args.get("handshake_messages") or [])
    own_subs = list(args.get("own_subscriptions") or [])
    victim_subs = list(args.get("victim_subscriptions") or [])
    allow_pattern = _re.compile(args.get("allow_pattern", r"SUBOK,{sub_id}"))
    deny_pattern = _re.compile(args.get("deny_pattern", r"REQERR,{sub_id}"))
    collect_seconds = float(args.get("collect_seconds", 5.0))

    async def _run() -> dict:
        try:
            import websockets
        except ModuleNotFoundError as exc:
            raise RuntimeError(
                "check_ws_idor requires the 'websockets' package: pip install websockets"
            ) from exc

        ssl_ctx = ssl.create_default_context() if ws_url.startswith("wss://") else None
        connect_kwargs: dict = {}
        if ws_protocol:
            connect_kwargs["subprotocols"] = [ws_protocol]
        if ssl_ctx:
            connect_kwargs["ssl"] = ssl_ctx

        collected: list[str] = []
        sent_log: list[str] = []

        async with websockets.connect(ws_url, **connect_kwargs) as ws:
            async def _drain(secs: float) -> None:
                deadline = asyncio.get_event_loop().time() + secs
                while True:
                    remaining = deadline - asyncio.get_event_loop().time()
                    if remaining <= 0:
                        break
                    try:
                        msg = await asyncio.wait_for(ws.recv(), timeout=min(remaining, 0.5))
                        collected.append(str(msg))
                    except (asyncio.TimeoutError, websockets.exceptions.ConnectionClosed):
                        break

            for msg in handshake_messages:
                await ws.send(str(msg))
                sent_log.append(str(msg)[:200])

            await _drain(2.0)

            all_subs = list(own_subs) + list(victim_subs)
            for sub in all_subs:
                await ws.send(str(sub["message"]))
                sent_log.append(str(sub["message"])[:200])

            await _drain(collect_seconds)

        raw = "\n".join(collected)

        def _classify(sub: dict) -> dict:
            sid = str(sub.get("sub_id", ""))
            allow_rx = _re.compile(allow_pattern.pattern.replace("{sub_id}", _re.escape(sid)))
            deny_rx = _re.compile(deny_pattern.pattern.replace("{sub_id}", _re.escape(sid)))
            if allow_rx.search(raw):
                status = "allowed"
            elif deny_rx.search(raw):
                status = "denied"
            else:
                status = "no_response"
            return {"id": sub.get("id"), "sub_id": sid, "status": status}

        own_results = [_classify(s) for s in own_subs]
        victim_results = [_classify(s) for s in victim_subs]

        own_allowed = all(r["status"] == "allowed" for r in own_results) if own_results else None
        victim_allowed_any = any(r["status"] == "allowed" for r in victim_results)
        victim_denied_all = all(r["status"] == "denied" for r in victim_results) if victim_results else False

        if victim_allowed_any:
            verdict = "IDOR_CONFIRMED"
            severity = "high"
        elif victim_denied_all and own_allowed:
            verdict = "access_control_enforced"
            severity = "none"
        elif not victim_results:
            verdict = "no_victim_subs_tested"
            severity = "none"
        else:
            verdict = "inconclusive"
            severity = "unknown"

        return {
            "url": ws_url,
            "verdict": verdict,
            "severity": severity,
            "own_baseline_ok": own_allowed,
            "own_subscriptions": own_results,
            "victim_subscriptions": victim_results,
            "raw_responses": raw[:4000],
        }

    return asyncio.run(_run())


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
        "change to a specific route. Active payloads (run_payloads) AND headless mode "
        "(which clicks buttons/links, not just a passive GET) are refused unless the "
        "target publishes a scan-policy consent manifest, or allow_without_policy is set.",
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
                "higher_priv_identity_markers": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Strings uniquely identifying the higher-priv account's "
                    "own data; a match in the lower-priv response upgrades the lead to "
                    "confidence=confirmed",
                },
                "lower_priv_identity_markers": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Strings identifying the lower-priv account's own data, "
                    "to rule out a coincidental higher_priv_identity_markers match",
                },
                "require_identity_confirmation": {
                    "type": "boolean",
                    "default": False,
                    "description": "Drop a lead entirely instead of reporting it unconfirmed",
                },
                "gql_field_names": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "GraphQL Query field names to replay when introspection is blocked",
                },
                "gql_schema": {
                    "type": "string",
                    "description": "Path to Clairvoyance / introspection JSON with Query field names",
                },
                "gql_wordlist": {
                    "type": "string",
                    "description": "Path to a plain field-name wordlist (one name per line)",
                },
            },
            "required": ["higher_priv_crawl"],
        },
        "handler": check_idor,
    },
    "peer_write": {
        "description": "Replay captured writes against known object ids as a second "
        "session. Compares each write to a nonsense-id control so a dummy 200 is "
        "not a finding. Not n±1 enumeration. Requires a scan-policy consent "
        "manifest unless allow_without_policy is set.",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "playbook": {
                    "description": "Playbook object, or a path to one, with target + writes",
                },
                "from_sessions": {
                    "type": "string",
                    "description": "HAR or proxy JSONL path; extract writes that name an id",
                },
                "target": {"type": "string"},
                "owner_cookie": {
                    "type": "string",
                    "description": "Cookie header for the owner verify re-read",
                },
                "peer_cookie": {
                    "type": "string",
                    "description": "Cookie header for the peer write replay",
                },
                "only_id": {"type": "string"},
                "rate": {"type": "number", "default": 1},
                "nonsense_id": {"type": "string", "default": "1"},
                "user_agent_suffix": {"type": "string"},
                "allow_external": {"type": "boolean", "default": False},
                "allow_without_policy": {"type": "boolean", "default": False},
                "policy_file": {"type": "string"},
                "audit_log": {"type": "string"},
                "csrf_from": {
                    "type": "string",
                    "description": "GET this URL to harvest a CSRF token before writes",
                },
                "no_csrf": {
                    "type": "boolean",
                    "default": False,
                    "description": "Do not harvest or attach CSRF tokens",
                },
                "require_confirm": {
                    "type": "boolean",
                    "default": False,
                    "description": "Only emit a finding when the owner re-read changed. Default true when both owner_cookie and peer_cookie are set.",
                },
                "allow_unconfirmed": {
                    "type": "boolean",
                    "default": False,
                    "description": "Emit probable leads even when both owner and peer cookies are set",
                },
            },
        },
        "handler": peer_write,
    },
    "session_export": {
        "description": "Write a Playwright storageState JSON from a HAR, proxy "
        "JSONL, Netscape jar, cookie pairs, or a Chrome --cdp URL. Requires "
        "origin. cdp/from require policy_file or allow_without_policy (this "
        "tool does not fetch scan-policy from the origin). ",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "from": {
                    "type": "string",
                    "description": "HAR, JSONL, Netscape, or storageState path",
                },
                "cdp": {"type": "string", "description": "Chrome DevTools URL"},
                "origin": {
                    "type": "string",
                    "description": "Absolute http(s) origin; required",
                },
                "cookie": {"type": "string", "description": "name=value (single pair)"},
                "allow_external": {
                    "type": "boolean",
                    "default": False,
                    "description": "Allow --cdp against a non-loopback DevTools URL",
                },
                "allow_without_policy": {
                    "type": "boolean",
                    "default": False,
                    "description": "Skip scan-policy when using cdp or from",
                },
                "policy_file": {
                    "type": "string",
                    "description": "Local scan-policy JSON (cdp only)",
                },
                "audit_log": {"type": "string"},
            },
        },
        "handler": session_export,
    },
    "extract_js_routes": {
        "description": "Extract parameterized URL templates ({userId}, {pk}, :id) "
        "from a local JavaScript file. Does not fetch or enumerate ids.",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "file": {"type": "string", "description": "Path to a local JS file"},
            },
            "required": ["file"],
        },
        "handler": extract_js_routes,
    },
    "paced_fetch": {
        "description": "GET a short list of URLs at a capped rate (default 1 req/s, "
        "max 20). For agent/Playwright loops against 1-req/s programs. Does not "
        "solve captchas. Requires a scan-policy consent manifest unless "
        "allow_without_policy is set.",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "urls": {"type": "array", "items": {"type": "string"}},
                "url": {"type": "string"},
                "method": {"type": "string", "enum": ["GET", "HEAD", "OPTIONS"], "default": "GET"},
                "cookie": {"type": "string"},
                "rate": {"type": "number", "default": 1},
                "user_agent_suffix": {"type": "string"},
                "allow_external": {"type": "boolean", "default": False},
                "allow_without_policy": {"type": "boolean", "default": False},
                "policy_file": {"type": "string"},
                "audit_log": {"type": "string"},
            },
        },
        "handler": paced_fetch,
    },
    "reverify_fix": {
        "description": "Re-scan one URL and report whether a specific finding_id is now "
        "gone -- closed-loop remediate-and-reverify. Call after patching source in "
        "response to a finding, before opening/merging a PR. Active payload re-runs "
        "require a scan-policy consent manifest by default, like scan_route. Check "
        "the result's 'warnings' list before trusting verified_fixed=true.",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "url": {"type": "string"},
                "finding_id": {"type": "string"},
                "mode": {"type": "string", "enum": ["static", "headless"], "default": "static"},
                "run_payloads": {"type": "boolean", "default": True},
                "allow_external": {"type": "boolean", "default": False},
                "allow_without_policy": {"type": "boolean", "default": False},
                "policy_file": {"type": "string"},
                "audit_log": {"type": "string"},
            },
            "required": ["url", "finding_id"],
        },
        "handler": reverify_fix,
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
    "check_ws_idor": {
        "description": "Test whether a WebSocket server enforces per-user subscription "
        "authorization. Connects with the provided credentials, sends handshake messages "
        "to establish a session, then probes victim-ID subscription groups and classifies "
        "each response as allowed/denied/no_response. Returns IDOR_CONFIRMED when any "
        "victim subscription is accepted, access_control_enforced when all are denied "
        "and the own-session baseline passes. Designed for Lightstreamer TLCP "
        "(SUBOK/REQERR) but configurable for any text-framed WS protocol.",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "ws_url": {
                    "type": "string",
                    "description": "WebSocket URL to connect to (ws:// or wss://)",
                },
                "ws_protocol": {
                    "type": "string",
                    "description": "WebSocket subprotocol (e.g. 'TLCP-2.5.0.lightstreamer.com')",
                },
                "handshake_messages": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Raw messages sent before subscriptions to establish the session "
                    "(e.g. 'wsok' then a full create_session line for Lightstreamer). "
                    "A 2-second drain follows before subscriptions are sent.",
                },
                "own_subscriptions": {
                    "type": "array",
                    "description": "Baseline subscriptions that should succeed (own-user IDs). "
                    "Each entry: {id: label, sub_id: int-or-string, message: raw-ws-string}.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string"},
                            "sub_id": {},
                            "message": {"type": "string"},
                        },
                        "required": ["sub_id", "message"],
                    },
                },
                "victim_subscriptions": {
                    "type": "array",
                    "description": "Subscriptions to test with victim-user IDs. Same shape as "
                    "own_subscriptions. A match in allow_pattern yields IDOR_CONFIRMED.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string"},
                            "sub_id": {},
                            "message": {"type": "string"},
                        },
                        "required": ["sub_id", "message"],
                    },
                },
                "allow_pattern": {
                    "type": "string",
                    "default": "SUBOK,{sub_id}",
                    "description": "Regex matching an 'accepted' server response. {sub_id} is "
                    "replaced with the subscription's sub_id value before matching "
                    "(e.g. 'SUBOK,{sub_id}' matches Lightstreamer SUBOK responses).",
                },
                "deny_pattern": {
                    "type": "string",
                    "default": "REQERR,{sub_id}",
                    "description": "Regex matching a 'denied' server response "
                    "(e.g. 'REQERR,{sub_id}' matches Lightstreamer SubscriptionNotAllowed).",
                },
                "collect_seconds": {
                    "type": "number",
                    "default": 5.0,
                    "description": "Seconds to collect server responses after sending all subscriptions.",
                },
            },
            "required": ["ws_url"],
        },
        "handler": check_ws_idor,
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
