"""CLI subcommand handlers.

Each cmd_* function implements one `shroodler` subcommand; cli.py wires them
into the argument parser. Split out of cli.py to keep that file to parsing.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from shroodler import __version__
from shroodler.baseline import document_to_baseline
from shroodler.diffcmd import diff_outcome, load_json
from shroodler.suppress import filter_findings, load_suppressions
from shroodler.validate import validate_crawl

_REPO_ROOT = Path(__file__).resolve().parents[3]


def _robots_flags(args: argparse.Namespace) -> tuple[bool, bool]:
    """Resolve (ignore_robots, harvest_robots) from --robots / --profile / the
    legacy --ignore-robots flag.

    safe=respect (honor Disallow), balanced=ignore (crawl through it),
    aggressive=harvest (seed and surface Disallow paths as recon leads).
    """
    mode = getattr(args, "robots", None)
    legacy_ignore = bool(getattr(args, "ignore_robots", False))
    if mode is None:
        return legacy_ignore, False
    mode = str(mode).lower()
    ignore = mode in ("ignore", "harvest") or legacy_ignore
    return ignore, mode == "harvest"


def _as_str_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    return []


def _write(text: str, output: str | None) -> None:
    if not text.endswith("\n"):
        text += "\n"
    if output:
        Path(output).write_text(text, encoding="utf-8")
    else:
        print(text, end="")


def _gql_field_names(args: argparse.Namespace) -> list[str]:
    from shroodler.extractors.graphql import load_graphql_field_names

    paths = list(getattr(args, "gql_schema", None) or [])
    paths.extend(getattr(args, "gql_wordlist", None) or [])
    if not paths:
        return []
    return load_graphql_field_names(paths)


def cmd_crawl(args: argparse.Namespace) -> int:
    depth = None if args.depth < 0 else args.depth
    max_pages = getattr(args, "max_pages", 400)
    max_time = getattr(args, "max_time", 0) or None
    # The safe profile's 60s budget is calibrated for static mode; headless
    # pages each take ~30s to render, so silently raise it to 600s when the
    # user combined --profile safe with --mode headless without an explicit
    # --max-time override.  balanced/aggressive already have no time limit.
    if (
        max_time is not None
        and max_time <= 60
        and getattr(args, "mode", "static") == "headless"
        and getattr(args, "profile", None) == "safe"
    ):
        max_time = 600.0
    cookies = list(getattr(args, "cookie", None) or [])
    headers = list(getattr(args, "header", None) or [])
    extra_seeds = list(getattr(args, "seed", None) or [])
    for spec_path in getattr(args, "spec", None) or []:
        from shroodler.extractors.openapi import urls_from_seed_file

        extra_seeds.extend(urls_from_seed_file(args.url, spec_path))
    cookies_from = getattr(args, "cookies_from", None)
    seed_from = getattr(args, "seed_from", None)
    if cookies_from or seed_from:
        from shroodler.cookie_source import load_captured_sessions
        from shroodler.sessions import cookie_header, seed_urls

        if cookies_from:
            hdr = cookie_header(load_captured_sessions(cookies_from), args.url)
            cookies.extend(p.strip() for p in hdr.split(";") if p.strip())
        if seed_from:
            extra_seeds.extend(seed_urls(load_captured_sessions(seed_from), args.url))
    ignore_robots, harvest_robots = _robots_flags(args)
    # The Go engine (shroodler-go) is the sole crawl engine. A handful of the
    # retired Python crawler's options have no Go equivalent; rather than
    # silently ignore them, refuse so the user is never misled about what ran.
    unsupported: list[str] = []
    if harvest_robots:
        unsupported.append("--robots harvest / --profile aggressive")
    if bool(getattr(args, "check_idor", False)):
        unsupported.append("--check-idor")
    if list(getattr(args, "plugin", None) or []):
        unsupported.append("--plugin")
    if list(getattr(args, "exclude_path", None) or []):
        unsupported.append("--exclude-path")
    if _gql_field_names(args):
        unsupported.append("--gql-schema / --gql-wordlist")
    if getattr(args, "from_capture", None):
        unsupported.append("--from-capture (use `shroodler ingest-sessions` instead)")
    if unsupported:
        print(
            "error: the Go crawl engine does not support: " + ", ".join(unsupported),
            file=sys.stderr,
        )
        return 2
    from shroodler import go_engine

    try:
        doc = go_engine.crawl(
            args.url,
            mode=args.mode,
            depth=depth if depth is not None else -1,
            ignore_robots=ignore_robots,
            allow_external=args.allow_external,
            max_pages=max_pages,
            max_time=max_time,
            cookies=cookies,
            headers=headers,
            cookie_jar=getattr(args, "cookie_jar", None),
            storage_state=getattr(args, "storage_state", None),
            login_recipe=getattr(args, "login_recipe", None),
            proxy=getattr(args, "proxy", None),
            seeds=extra_seeds,
            no_sitemap=bool(getattr(args, "no_sitemap", False)),
            check_rate_limit=bool(getattr(args, "check_rate_limit", False)),
            user_agent=getattr(args, "user_agent", None),
        )
    except go_engine.GoEngineError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    validate_crawl(doc)
    fmt = args.format
    if fmt == "json":
        text = json.dumps(doc, indent=2) + "\n"
    else:
        from shroodler.report import write_report

        text = write_report(doc, fmt, None)
        if not text.endswith("\n"):
            text += "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    program_slug = getattr(args, "program", None)
    if program_slug:
        from shroodler.program import load, merge_crawl_doc, save

        state = load(program_slug)
        delta = merge_crawl_doc(state, doc)
        save(state)
        print(
            f"program {program_slug}: +{delta['new_endpoints']} endpoints, "
            f"+{delta['new_findings']} findings, "
            f"{delta['object_id_values']} object ids",
            file=sys.stderr,
        )
    return 0


def _warn_expired_suppressions(rules: list[dict]) -> None:
    from shroodler.suppress import expired_suppressions, expires_malformed

    # A warning, not a failure, and every command that loads
    # suppressions prints it (not just `diff`): a rule that ages out
    # silently is easy to miss, and worse, silently baking its
    # now-unsuppressed finding into a NEW baseline/report as if it were
    # freshly accepted is the failure mode this exists to prevent (a
    # suppression is supposed to force periodic re-review, not quietly
    # become permanent the next time someone regenerates a baseline).
    #
    # Deliberately does NOT claim "no longer suppressing": another,
    # broader rule (a wildcard id="*"/url="*" a mature ignore-file tends
    # to accumulate) may still cover the same finding, and asserting
    # enforcement resumed when it may not have would be actively
    # misleading rather than merely incomplete.
    for rule in expired_suppressions(rules):
        what = (
            "has an unparseable expires value (expected YYYY-MM-DD), treated as expired"
            if expires_malformed(rule)
            else f"expired {rule['expires']!r}"
        )
        print(
            f"suppression {what}: id={rule['id']!r} url={rule['url']!r} "
            f"owner={rule['owner'] or '(unset)'!r} reason={rule['reason'] or '(none)'!r} "
            "-- this rule no longer applies (another rule may still cover the finding)",
            file=sys.stderr,
        )


def _attribute_new_findings(new_findings: list[dict], source_root: str) -> tuple[dict, bool]:
    from shroodler.code_attribution import attribute_findings
    from shroodler.diffcmd import finding_key

    root = Path(source_root)
    # One shared SourceIndex walk/read for every new finding in this run,
    # not one per finding -- a --gate run with many new findings against
    # a large repo would otherwise re-walk and re-read the whole tree
    # once per finding.
    batch = attribute_findings(root, [f.get("url", "") for f in new_findings])
    attributions = {
        finding_key(f): batch.by_url[f.get("url", "")]
        for f in new_findings
        if f.get("url", "") in batch.by_url
    }
    return attributions, batch.exhausted


def cmd_diff(args: argparse.Namespace) -> int:
    actual = load_json(args.findings)
    expected = load_json(args.expected)
    rules = load_suppressions(getattr(args, "suppressions", None))
    _warn_expired_suppressions(rules)
    outcome = diff_outcome(
        actual,
        expected,
        pages_only=args.pages_only,
        gate=bool(getattr(args, "gate", False)),
        suppressions=rules,
    )
    source_root = getattr(args, "source_root", None)
    attributions: dict = {}
    attribution_exhausted = False
    if source_root:
        attributions, attribution_exhausted = _attribute_new_findings(
            outcome.new_findings, source_root
        )

    fmt = getattr(args, "format", "text") or "text"
    output = getattr(args, "output", None)
    if fmt in {"junit", "sarif"}:
        from shroodler.report import render_diff_junit, render_diff_sarif

        text = (
            render_diff_junit(outcome.errors)
            if fmt == "junit"
            else render_diff_sarif(outcome.errors)
        )
        _write(text, output)
        return 1 if outcome.errors else 0
    if fmt == "github-annotations":
        from shroodler.diffcmd import finding_key

        lines = []
        for f in outcome.new_findings:
            attribution = attributions.get(finding_key(f))
            desc = f.get("description") or f.get("id", "")
            if attribution:
                lines.append(
                    f"::error file={attribution['file']},line={attribution['line']}::"
                    f"{f.get('id')} at {f.get('url')} -- {desc} "
                    f"(commit {attribution.get('commit', '?')})"
                )
            else:
                lines.append(f"::error::{f.get('id')} at {f.get('url')} -- {desc}")
        for err in outcome.errors:
            if not err.startswith("new finding"):
                lines.append(f"::error::{err}")
        if attribution_exhausted:
            lines.append(
                "::warning::--source-root attribution hit its file-count/memory "
                "budget before finishing -- some findings above may be unattributed "
                "only because the walk was cut short"
            )
        text = "\n".join(lines) + ("\n" if lines else "")
        _write(text, output)
        return 1 if outcome.errors else 0
    for line in outcome.resolved:
        print(line)
    if outcome.errors:
        from shroodler.diffcmd import finding_key

        for err in outcome.errors:
            print(err, file=sys.stderr)
        for f in outcome.new_findings:
            attribution = attributions.get(finding_key(f))
            if attribution:
                where = f"{attribution['file']}:{attribution['line']}"
                commit_note = ""
                if "commit" in attribution:
                    commit_note = (
                        f" (commit {attribution['commit']} by "
                        f"{attribution['author']} on {attribution['date']})"
                    )
                msg = (
                    f"  -> {f.get('id')} at {f.get('url')} "
                    f"looks introduced by {where}{commit_note}"
                )
                print(msg, file=sys.stderr)
        if attribution_exhausted:
            print(
                "note: --source-root attribution hit its file-count/memory budget "
                "before finishing -- some findings above may be unattributed only "
                "because the walk was cut short, not because no route source exists",
                file=sys.stderr,
            )
        return 1
    print("diff ok")
    return 0


def cmd_eval(args: argparse.Namespace) -> int:
    import json as _json

    from shroodler import eval_harness as ev

    try:
        actual = ev.load_json(args.actual)
        expected = ev.load_json(args.expected)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    card = ev.score(actual, expected, label=str(getattr(args, "label", "") or "run"))
    result: dict = {"scorecard": card.to_dict()}
    if getattr(args, "baseline", None):
        try:
            baseline_doc = ev.load_json(args.baseline)
        except (OSError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        base_card = ev.score(baseline_doc, expected, label="baseline")
        result["baseline"] = base_card.to_dict()
        result["comparison"] = ev.compare(base_card, card)
    if getattr(args, "json", False):
        print(_json.dumps(result, indent=2))
        return 0
    print(ev.format_scorecard(card))
    if "comparison" in result:
        comp = result["comparison"]
        print("\nA/B vs baseline:")
        print(f"  Δ true positives : {comp['delta_true_positives']:+d}")
        print(f"  Δ false positives: {comp['delta_false_positives']:+d}")
        print(f"  Δ recall         : {comp['delta_recall']:+.2%}")
        print(f"  Δ precision      : {comp['delta_precision']:+.2%}")
        if comp["newly_found"]:
            print(f"  newly found      : {', '.join(comp['newly_found'][:10])}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    from shroodler.report import write_report

    doc = load_json(args.findings)
    rules = load_suppressions(getattr(args, "suppressions", None))
    _warn_expired_suppressions(rules)
    merge_paths = list(getattr(args, "merge_sarif", None) or [])
    if merge_paths:
        from shroodler.confidence import stamp_findings
        from shroodler.report import findings_from_sarif, merge_findings

        extra: list[dict] = []
        default_url = str(doc.get("target") or "")
        for path in merge_paths:
            sarif_doc = json.loads(Path(path).read_text(encoding="utf-8"))
            extra.extend(findings_from_sarif(sarif_doc, default_url=default_url))
        stamp_findings(extra)
        doc = dict(doc)
        doc["findings"] = merge_findings(list(doc.get("findings") or []), extra)
    if rules:
        doc = dict(doc)
        doc["findings"] = filter_findings(doc.get("findings") or [], rules)
    if getattr(args, "dedup", True):
        from shroodler.dedup import deduplicate

        doc = dict(doc)
        doc["findings"] = deduplicate(list(doc.get("findings") or []))
    if args.format == "json":
        text = json.dumps(doc, indent=2) + "\n"
        _write(text, args.output)
        return 0
    text = write_report(doc, args.format, args.output)
    if not args.output:
        print(text, end="" if text.endswith("\n") else "\n")
    return 0


def cmd_ingest(args: argparse.Namespace) -> int:
    from shroodler.sessions import ingest_sessions

    result = ingest_sessions(
        args.sessions,
        target=args.target,
        allow_external=args.allow_external,
    )
    doc = result.to_dict()
    validate_crawl(doc)
    text = json.dumps(doc, indent=2) + "\n"
    _write(text, args.output)
    return 0


def cmd_tokens(args: argparse.Namespace) -> int:
    from shroodler.sessions import load_sessions
    from shroodler.token_entropy import analyze_tokens

    # Unlike ingest-sessions/crawl, this never makes a network request or
    # scans anything -- it only analyzes a JSONL file the user already
    # has locally -- so there's no --allow-external-style host guard: a
    # single recording can legitimately span several hosts (the app
    # under test plus, e.g., a third-party IdP), and there's no "the
    # target" to check against the way there is for a live scan.
    sessions = load_sessions(args.sessions)
    findings = analyze_tokens(sessions)
    doc = {"target": args.sessions, "findings": [f.model_dump() for f in findings]}
    text = json.dumps(doc, indent=2) + "\n"
    _write(text, args.output)
    return 0


def cmd_authz_diff(args: argparse.Namespace) -> int:
    from shroodler.auth import parse_cookie_pairs, parse_header_lines
    from shroodler.authz_diff import run as authz_diff_run

    higher_doc = load_json(args.higher_crawl_json)
    cookie_pairs = parse_cookie_pairs(list(getattr(args, "cookie", None) or []))
    cookie_header = "; ".join(f"{c.name}={c.value}" for c in cookie_pairs)
    extra_headers = parse_header_lines(list(getattr(args, "header", None) or []))

    enforcer = None
    require_policy = getattr(args, "require_policy", False)
    policy_file = getattr(args, "policy_file", None)
    audit_log = getattr(args, "audit_log", None)
    if require_policy or policy_file or audit_log:
        from shroodler_guardrails.policy import (
            PolicyEnforcer,
            fetch_policy,
            origin_of,
            parse_policy,
        )

        if policy_file:
            manifest = json.loads(Path(policy_file).read_text(encoding="utf-8"))
            policy = parse_policy(manifest, origin=origin_of(higher_doc.get("target", "")))
        else:
            policy = fetch_policy(higher_doc.get("target", ""))
        enforcer = PolicyEnforcer(
            policy=policy,
            require_policy=require_policy,
            audit_path=Path(audit_log) if audit_log else None,
        )

    out = authz_diff_run(
        higher_doc,
        cookie_header=cookie_header,
        extra_headers=extra_headers,
        check_anonymous=not bool(getattr(args, "no_anon_check", False)),
        allow_external=bool(getattr(args, "allow_external", False)),
        enforcer=enforcer,
        higher_priv_identity_markers=list(getattr(args, "higher_priv_marker", None) or []),
        lower_priv_identity_markers=list(getattr(args, "lower_priv_marker", None) or []),
        require_identity_confirmation=bool(getattr(args, "require_identity_confirmation", False)),
        gql_field_names=_gql_field_names(args),
    )
    program_slug = getattr(args, "program", None)
    if program_slug:
        from shroodler.program import load, mark_tested, save

        state = load(program_slug)
        urls = [str(p.get("url") or "") for p in (higher_doc.get("pages") or [])]
        mark_tested(state, urls, "tested_authz")
        save(state)
    text = json.dumps(out, indent=2) + "\n"
    _write(text, args.output)
    return 0


def _policy_enforcer(args: argparse.Namespace, target: str):
    require_policy = getattr(args, "require_policy", False)
    policy_file = getattr(args, "policy_file", None)
    audit_log = getattr(args, "audit_log", None)
    if not (require_policy or policy_file or audit_log):
        return None
    from shroodler_guardrails.policy import (
        PolicyEnforcer,
        fetch_policy,
        origin_of,
        parse_policy,
    )

    if policy_file:
        manifest = json.loads(Path(policy_file).read_text(encoding="utf-8"))
        policy = parse_policy(manifest, origin=origin_of(target))
    else:
        policy = fetch_policy(target)
    return PolicyEnforcer(
        policy=policy,
        require_policy=require_policy,
        audit_path=Path(audit_log) if audit_log else None,
    )


def cmd_peer_write(args: argparse.Namespace) -> int:
    from shroodler.auth import parse_header_lines
    from shroodler.cookie_source import resolve_cookie_header
    from shroodler.peer_write import load_playbook
    from shroodler.peer_write import run as peer_write_run

    playbook: dict = {}
    if getattr(args, "playbook", None):
        playbook = load_json(args.playbook)
        if not isinstance(playbook, dict):
            raise ValueError("playbook must be a JSON object")
    if not playbook and not getattr(args, "from_sessions", None):
        raise ValueError("peer-write needs a playbook.json or --from-sessions")
    if args.target:
        playbook["target"] = args.target

    merged = load_playbook(
        playbook,
        sessions_path=getattr(args, "from_sessions", None),
        target=str(playbook.get("target") or args.target or ""),
        only_id=getattr(args, "only_id", None),
    )
    from_program = getattr(args, "from_program", None)
    if from_program:
        from shroodler.program import apply_program_ids
        from shroodler.program import load as load_program

        state = load_program(from_program)
        merged = apply_program_ids(
            merged, state, only_id=getattr(args, "only_id", None)
        )
    target = str(merged.get("target") or "")
    owner_cookie = resolve_cookie_header(
        pairs=list(getattr(args, "owner_cookie", None) or []),
        path=getattr(args, "owner_cookies_from", None),
        origin_url=target,
    )
    peer_cookie = resolve_cookie_header(
        pairs=list(getattr(args, "peer_cookie", None) or []),
        path=getattr(args, "peer_cookies_from", None),
        origin_url=target,
    )
    extra_headers = parse_header_lines(list(getattr(args, "header", None) or []))
    require_confirm = bool(getattr(args, "require_confirm", False))
    allow_unconfirmed = bool(getattr(args, "allow_unconfirmed", False))
    if owner_cookie and peer_cookie and not allow_unconfirmed:
        require_confirm = True
    out = peer_write_run(
        merged,
        owner_cookie=owner_cookie,
        peer_cookie=peer_cookie,
        extra_headers=extra_headers,
        allow_external=bool(getattr(args, "allow_external", False)),
        enforcer=_policy_enforcer(args, target),
        rate=float(getattr(args, "rate", 1.0) or 1.0),
        user_agent=getattr(args, "user_agent", None) or "",
        user_agent_suffix=getattr(args, "user_agent_suffix", None) or "",
        nonsense_id=str(getattr(args, "nonsense_id", None) or "1"),
        only_id=getattr(args, "only_id", None),
        csrf=not bool(getattr(args, "no_csrf", False)),
        csrf_from=str(getattr(args, "csrf_from", None) or ""),
        require_confirm=require_confirm,
        allow_unconfirmed=allow_unconfirmed,
    )
    program_slug = getattr(args, "program", None)
    if program_slug:
        from shroodler.program import load as load_program
        from shroodler.program import mark_tested, save

        state = load_program(program_slug)
        urls = [str(w.get("url") or "") for w in (merged.get("writes") or [])]
        mark_tested(state, urls, "tested_peer_write")
        save(state)
    text = json.dumps(out, indent=2) + "\n"
    _write(text, args.output)
    return 0


def cmd_session_export(args: argparse.Namespace) -> int:
    from shroodler.session_export import export_session

    doc = export_session(
        source=getattr(args, "source", None),
        cdp=getattr(args, "cdp", None),
        origin=str(getattr(args, "origin", None) or ""),
        pairs=list(getattr(args, "cookie", None) or []),
        allow_external=bool(getattr(args, "allow_external", False)),
    )
    text = json.dumps(doc, indent=2) + "\n"
    _write(text, args.output)
    return 0


def cmd_js_routes(args: argparse.Namespace) -> int:
    from shroodler.extractors.js_routes import extract_js_routes_file

    out = extract_js_routes_file(args.js_file)
    text = json.dumps(out, indent=2) + "\n"
    _write(text, args.output)
    return 0


def cmd_program_init(args: argparse.Namespace) -> int:
    from shroodler.program import load, load_scope_file, save

    state = load(args.slug)
    scope_file = getattr(args, "scope_file", None)
    if scope_file:
        ins, out = load_scope_file(scope_file)
        state.scope_urls = ins
        state.scope_out = out
        save(state)
    print(f"program {state.slug}: {len(state.endpoints)} endpoints")
    return 0


def cmd_program_status(args: argparse.Namespace) -> int:
    from shroodler.program import as_briefing, coverage_gaps, load, stale_sessions

    state = load(args.slug)
    briefing = as_briefing(state)
    gaps = coverage_gaps(state)
    stale = stale_sessions(state)
    lines = [
        f"program {state.slug}",
        f"endpoints: {briefing['endpoint_count']}",
        f"findings: {briefing['finding_count']}",
        f"coverage gaps: {briefing['coverage_gap_count']}",
        f"unconfirmed leads: {briefing['unconfirmed_leads']}",
        f"stale sessions: {len(stale)}",
    ]
    if briefing.get("stale_session_warning"):
        lines.append(briefing["stale_session_warning"])
    if gaps:
        lines.append("top coverage gaps:")
        for gap in gaps[:10]:
            flags = []
            if not gap["tested_authz"]:
                flags.append("authz")
            if not gap["tested_peer_write"]:
                flags.append("peer-write")
            lines.append(f"  {gap['url']}  missing={','.join(flags)}  last_seen={gap['last_seen']}")
    print("\n".join(lines))
    return 0


def cmd_program_merge(args: argparse.Namespace) -> int:
    from shroodler.program import load, merge_crawl, save

    state = load(args.slug)
    delta = merge_crawl(state, args.crawl_json)
    save(state)
    print(
        json.dumps(
            {"slug": state.slug, **delta, "endpoints": len(state.endpoints)},
            indent=2,
        )
    )
    return 0


def cmd_agent(args: argparse.Namespace) -> int:
    from shroodler.agent import AgentConfig, run_agent

    config = AgentConfig(
        program=str(args.program),
        target=str(args.target),
        max_iterations=int(getattr(args, "max_iterations", 10) or 10),
        max_pages_per_crawl=int(getattr(args, "max_pages_per_crawl", 30) or 30),
        login_recipe=getattr(args, "login_recipe", None),
        peer_recipe=getattr(args, "peer_recipe", None),
        reauth_max_retries=int(getattr(args, "reauth_max_retries", 3) or 3),
        higher_priv_jar=getattr(args, "higher_priv_jar", None),
        lower_priv_jar=getattr(args, "lower_priv_jar", None),
        owner_cookie=getattr(args, "owner_cookie", None),
        peer_cookie=getattr(args, "peer_cookie", None),
        dry_run=bool(getattr(args, "dry_run", False)),
        llm_triage=bool(getattr(args, "llm_triage", False)),
        run_discovery=bool(getattr(args, "run_discovery", False)),
        ignore_robots=_robots_flags(args)[0],
        harvest_robots=_robots_flags(args)[1],
        write_authz_spec=getattr(args, "write_authz_spec", None),
        run_probes=bool(getattr(args, "run_probes", False)),
        probe_time_sqli=not bool(getattr(args, "no_time_sqli", False)),
        reprobe=bool(getattr(args, "reprobe", False)),
        run_diff=bool(getattr(args, "run_diff", False)),
        run_business_logic=bool(getattr(args, "llm_business_logic", False)),
        chain_specs=list(getattr(args, "chain_spec", None) or []),
        workflow_mutate=bool(getattr(args, "workflow_mutate", False)),
        run_openapi_discovery=not bool(getattr(args, "no_openapi", False)),
        run_openapi_probes=not bool(getattr(args, "no_openapi", False)),
        run_ssrf=not bool(getattr(args, "no_ssrf", False)),
        run_open_redirect=not bool(getattr(args, "no_open_redirect", False)),
        run_host_header=not bool(getattr(args, "no_host_header", False)),
        run_ssti=not bool(getattr(args, "no_ssti", False)),
        run_xxe=not bool(getattr(args, "no_xxe", False)),
        run_graphql=not bool(getattr(args, "no_graphql", False)),
        auto_register=not bool(getattr(args, "no_auto_register", False)),
        run_dom_xss=bool(getattr(args, "dom_xss", False)),
        run_crlf=not bool(getattr(args, "no_crlf", False)),
        run_prototype_pollution=not bool(getattr(args, "no_prototype_pollution", False)),
        run_content_discovery=not bool(getattr(args, "no_content_discovery", False)),
        run_tls_check=not bool(getattr(args, "no_tls_check", False)),
        run_rate_limit=not bool(getattr(args, "no_rate_limit_check", False)),
        run_mass_assignment=not bool(getattr(args, "no_mass_assignment", False)),
        aggressive=bool(getattr(args, "aggressive", False)),
        run_smuggling=(
            bool(getattr(args, "smuggling", False))
            or bool(getattr(args, "aggressive", False))
        )
        and not bool(getattr(args, "no_smuggling", False)),
        run_websocket=not bool(getattr(args, "no_websocket", False)),
        allow_external=bool(getattr(args, "allow_external", False)),
        scope_file=getattr(args, "scope_file", None),
        context_note=str(getattr(args, "context", None) or ""),
        prove_impact=bool(getattr(args, "prove_impact", False)),
        llm_agent=bool(getattr(args, "llm_agent", False)),
        llm_provider=str(getattr(args, "llm_provider", None) or "deepseek"),
        llm_agent_model=str(
            getattr(args, "llm_agent_model", None) or "deepseek-chat"
        ),
        llm_agent_reasoning_model=str(
            getattr(args, "llm_agent_reasoning_model", None) or "deepseek-reasoner"
        ),
        llm_auto_verify=not bool(getattr(args, "no_auto_verify", False)),
        llm_verify=bool(getattr(args, "llm_verify", False)),
        llm_agent_max_cost_usd=(
            5.0
            if getattr(args, "llm_agent_max_cost", None) is None
            else float(args.llm_agent_max_cost)
        ),
        run_js_analysis=not bool(getattr(args, "no_js_analysis", False)),
        run_waf_detect=not bool(getattr(args, "no_waf_detect", False)),
        oob=bool(getattr(args, "oob", False)),
        oob_listen=str(getattr(args, "oob_listen", None) or "127.0.0.1:8765"),
        oob_public_url=str(getattr(args, "oob_public_url", None) or ""),
    )
    if config.llm_agent or config.llm_verify:
        from shroodler.llm_provider import llm_api_key_env, provider_requires_api_key

        if provider_requires_api_key(config.llm_provider):
            env_name = llm_api_key_env(config.llm_provider)
            if not os.environ.get(env_name):
                flag = "--llm-agent" if config.llm_agent else "--llm-verify"
                print(f"error: {flag} requires {env_name}", file=sys.stderr)
                return 2
    try:
        result = run_agent(config)
    except Exception as exc:
        from shroodler.oob import OOBError

        if isinstance(exc, OOBError):
            print(f"error: {exc}", file=sys.stderr)
            return 2
        raise
    payload: dict = {
        "iterations": result.iterations,
        "confirmed": result.confirmed,
        "state_path": result.state_path,
    }
    if config.llm_agent:
        payload["cost_usd"] = round(float(getattr(config, "_llm_cost_usd", 0.0) or 0.0), 6)
    if result.errors:
        payload["errors"] = result.errors
    print(json.dumps(payload))
    return 0


def cmd_discover(args: argparse.Namespace) -> int:
    from shroodler.discovery import DiscoveryConfig, discover
    from shroodler.program import load

    state = load(str(args.program))
    config = DiscoveryConfig(
        target=str(args.target),
        max_subdomains=int(getattr(args, "max_subdomains", 300) or 300),
        probe_workers=int(getattr(args, "probe_workers", 20) or 20),
        skip_crtsh=bool(getattr(args, "skip_crtsh", False)),
        skip_js_surface=bool(getattr(args, "skip_js_surface", False)),
        dry_run=bool(getattr(args, "dry_run", False)),
    )
    result = discover(state, str(args.target), config)
    print(
        json.dumps(
            {
                "subdomains_found": len(result.subdomains_found),
                "subdomains_added": result.subdomains_added_to_state,
                "endpoints_found": len(result.endpoints_found),
                "elapsed_ms": result.elapsed_ms,
            }
        )
    )
    return 0


def cmd_program_add_session(args: argparse.Namespace) -> int:
    from shroodler.program import add_session, load, save

    state = load(args.slug)
    record = add_session(
        state,
        args.path,
        label=args.label,
        expires=getattr(args, "expires", None),
    )
    save(state)
    print(json.dumps(record, indent=2))
    return 0


def cmd_paced_fetch(args: argparse.Namespace) -> int:
    from shroodler.auth import parse_cookie_pairs, parse_header_lines
    from shroodler.cookie_source import cookie_header_from_specs
    from shroodler.paced_fetch import fetch_urls

    urls = list(getattr(args, "url", None) or [])
    urls_file = getattr(args, "urls_file", None)
    if urls_file:
        urls.extend(
            ln.strip()
            for ln in Path(urls_file).read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        )
    if not urls:
        raise ValueError("paced-fetch needs --url or --urls-file")
    cookie_pairs = parse_cookie_pairs(list(getattr(args, "cookie", None) or []))
    cookie_header = cookie_header_from_specs(cookie_pairs)
    extra_headers = parse_header_lines(list(getattr(args, "header", None) or []))
    target = next((u for u in urls if "://" in u), urls[0])
    out = fetch_urls(
        urls,
        method=getattr(args, "method", None) or "GET",
        cookie_header=cookie_header,
        extra_headers=extra_headers,
        allow_external=bool(getattr(args, "allow_external", False)),
        enforcer=_policy_enforcer(args, target),
        rate=float(getattr(args, "rate", 1.0) or 1.0),
        user_agent=getattr(args, "user_agent", None) or "",
        user_agent_suffix=getattr(args, "user_agent_suffix", None) or "",
    )
    text = json.dumps(out, indent=2) + "\n"
    _write(text, args.output)
    return 0


def cmd_baseline(args: argparse.Namespace) -> int:
    doc = load_json(args.findings)
    rules = load_suppressions(args.suppressions)
    # Specifically important here, not just consistency: baseline is the
    # command that turns "not suppressed" into "permanently accepted" --
    # regenerating a baseline after a suppression expired silently bakes
    # that now-unsuppressed finding in as freshly-accepted, unattributed
    # risk, which is exactly backwards for a mechanism meant to force
    # periodic re-review. This at least makes that visible.
    _warn_expired_suppressions(rules)
    baseline = document_to_baseline(doc, name=args.name, suppressions=rules)
    text = json.dumps(baseline, indent=2) + "\n"
    _write(text, args.output)
    return 0


def _history_dir(args: argparse.Namespace) -> Path:
    from shroodler.history import default_history_dir

    override = getattr(args, "history_dir", None)
    return Path(override) if override else default_history_dir()


def cmd_history_record(args: argparse.Namespace) -> int:
    from shroodler.history import record_scan

    doc = load_json(args.findings)
    path = record_scan(doc, _history_dir(args), label=getattr(args, "label", None))
    print(str(path))
    return 0


def cmd_history_list(args: argparse.Namespace) -> int:
    from shroodler.history import list_scans

    entries = list_scans(_history_dir(args), target=getattr(args, "target", None))
    if getattr(args, "format", "text") == "json":
        print(json.dumps(entries, indent=2))
        return 0
    if not entries:
        print("no recorded scans")
        return 0
    for e in entries:
        print(f"{e['id']}  {e['scanned_at']}  {e['findings']:>4} findings  {e['target']}")
    return 0


def cmd_trend(args: argparse.Namespace) -> int:
    from shroodler.history import load_scan, render_trend_text, trend_diff

    history_dir = _history_dir(args)
    older = load_scan(history_dir, args.older)
    newer = load_scan(history_dir, args.newer)
    rules = load_suppressions(getattr(args, "suppressions", None))
    _warn_expired_suppressions(rules)
    if rules:
        # A finding the team has formally accepted via a suppression
        # rule shouldn't be able to fail --gate-on-severity-increase --
        # every other gate-capable command (diff, and the checks that
        # feed report/baseline) honors suppressions, and this is the
        # one CI-facing command that didn't.
        older = dict(older, findings=filter_findings(older.get("findings", []), rules))
        newer = dict(newer, findings=filter_findings(newer.get("findings", []), rules))
    trend = trend_diff(older, newer)

    from shroodler.waf_coverage import waf_coverage_regression

    waf_finding = waf_coverage_regression(
        older, newer, drop_threshold=float(getattr(args, "waf_drop_threshold", 0.2) or 0.2)
    )
    trend["waf_coverage_regression"] = waf_finding

    if getattr(args, "format", "text") == "json":
        text = json.dumps(trend, indent=2) + "\n"
    else:
        text = render_trend_text(trend)
        if waf_finding:
            text += (
                f"\nWAF coverage regression ({waf_finding['severity']}): "
                f"{waf_finding['description']}\n"
            )
    _write(text, args.output)
    failing = False
    if bool(getattr(args, "gate_on_severity_increase", False)) and trend["severity_increased"]:
        for f in trend["severity_increased"]:
            msg = f"severity increased: {f['id']} @ {f['url']}: {f['from']} -> {f['to']}"
            print(msg, file=sys.stderr)
        failing = True
    if bool(getattr(args, "gate_on_waf_coverage_drop", False)) and waf_finding:
        if waf_finding["page_count_mismatch"] and not getattr(
            args, "gate_even_if_page_count_mismatch", False
        ):
            print(
                "waf coverage regression NOT gated: the two scans crawled very "
                "different numbers of pages, so this comparison may not be "
                "meaningful -- pass --gate-even-if-page-count-mismatch to gate on it "
                f"anyway. {waf_finding['description']}",
                file=sys.stderr,
            )
        else:
            print(f"waf coverage regression: {waf_finding['description']}", file=sys.stderr)
            failing = True
    return 1 if failing else 0


def _payload_tester_dir() -> Path:
    env = os.environ.get("SHROODLER_PAYLOAD_DIR")
    if env:
        cand = Path(env)
        if (cand / "tester.py").is_file():
            return cand
        raise FileNotFoundError(f"payload-tester not found in {cand}")
    for parent in Path(__file__).resolve().parents:
        for cand in (
            parent / "packages" / "payload-tester",
            parent / "payload-tester",
        ):
            if (cand / "tester.py").is_file():
                return cand
    raise FileNotFoundError("payload-tester not found; set SHROODLER_PAYLOAD_DIR")


def cmd_nuclei_ingest(args: argparse.Namespace) -> int:
    tester_dir = _payload_tester_dir()
    if str(tester_dir) not in sys.path:
        sys.path.insert(0, str(tester_dir))
    import nuclei_ingest

    paths = [Path(p) for p in args.templates]
    packs, skipped = nuclei_ingest.convert_files(paths)
    for note in skipped:
        print(f"warning: {note}", file=sys.stderr)
    text = nuclei_ingest.dumps_pack(packs)
    _write(text, args.output)
    return 0 if packs else 1


def cmd_slither_ingest(args: argparse.Namespace) -> int:
    from shroodler.slither_ingest import convert_file

    result = convert_file(args.report, target=getattr(args, "target", None))
    doc = result.to_dict()
    validate_crawl(doc)
    text = json.dumps(doc, indent=2) + "\n"
    _write(text, args.output)
    return 0


def cmd_payload(args: argparse.Namespace) -> int:
    tester_dir = _payload_tester_dir()
    if str(tester_dir) not in sys.path:
        sys.path.insert(0, str(tester_dir))
    import tester

    extra = [Path(x) for x in (getattr(args, "pack", None) or [])]
    from shroodler.plugins import load_plugins, merge_payload_paths, plugin_paths_from_env

    plugin_dirs = plugin_paths_from_env(getattr(args, "plugin", None) or [])
    if plugin_dirs:
        extra.extend(merge_payload_paths(load_plugins(plugin_dirs)))
    doc = load_json(args.crawl_json)
    packs = tester.load_packs(extra=extra) if extra else tester.load_packs()

    enforcer = None
    require_policy = getattr(args, "require_policy", False)
    policy_file = getattr(args, "policy_file", None)
    audit_log = getattr(args, "audit_log", None)
    if require_policy or policy_file or audit_log:
        from shroodler_guardrails.policy import (
            PolicyEnforcer,
            fetch_policy,
            origin_of,
            parse_policy,
        )

        if policy_file:
            manifest = json.loads(Path(policy_file).read_text(encoding="utf-8"))
            policy = parse_policy(manifest, origin=origin_of(doc.get("target", "")))
        else:
            policy = fetch_policy(doc.get("target", ""))
        enforcer = PolicyEnforcer(
            policy=policy,
            require_policy=require_policy,
            audit_path=Path(audit_log) if audit_log else None,
        )

    out = tester.run(
        doc,
        packs=packs,
        allow_external=getattr(args, "allow_external", False),
        oob_host=getattr(args, "oob_host", None),
        enforcer=enforcer,
        adaptive=bool(getattr(args, "adaptive", False)),
        csrf=not bool(getattr(args, "no_csrf", False)),
    )
    text = json.dumps(out, indent=2) + "\n"
    _write(text, args.output)
    return 0


def find_proxy_bin() -> Path | None:
    env = os.environ.get("SHROODLER_PROXY_BIN")
    if env:
        path = Path(env)
        return path if path.is_file() else None
    which = shutil.which("shroodler-proxy")
    if which:
        return Path(which)
    for root in (_REPO_ROOT, Path.cwd()):
        cand = root / "packages" / "proxy-go" / "shroodler-proxy"
        if cand.is_file():
            return cand
    return None


def cmd_suppress_expiring(args: argparse.Namespace) -> int:
    from shroodler.suppress import expiring_within, render_expiring_pr_body

    rules = load_suppressions(args.suppressions)
    expiring = expiring_within(rules, args.days)
    if args.format == "json":
        text = json.dumps(expiring, indent=2) + "\n"
    elif args.format == "github-pr-body":
        text = render_expiring_pr_body(expiring, args.days)
    else:
        if not expiring:
            text = f"No suppression rules expire within the next {args.days} day(s).\n"
        else:
            lines = [
                f"id={r['id']!r} url={r['url']!r} expires={r['expires']} "
                f"owner={r['owner'] or '(unset)'!r} reason={r['reason'] or '(none)'!r}"
                for r in expiring
            ]
            text = "\n".join(lines) + "\n"
    _write(text, args.output)
    return 1 if (args.gate and expiring) else 0


def cmd_engagement_suppress(args: argparse.Namespace) -> int:
    from shroodler.program import load, save, suppress_finding

    slug = str(getattr(args, "program", None) or "")
    finding_id = str(getattr(args, "finding_id", None) or "")
    url = str(getattr(args, "url", None) or "*")
    reason = str(getattr(args, "reason", None) or "")
    if not slug or not finding_id:
        print(
            "error: suppress --program SLUG --id FINDING_ID --url URL --reason TEXT",
            file=sys.stderr,
        )
        return 2
    state = load(slug)
    suppress_finding(state, finding_id, url, reason)
    save(state)
    print(
        json.dumps(
            {
                "program": slug,
                "id": finding_id,
                "url": url,
                "reason": reason,
                "suppressed": True,
            }
        )
    )
    return 0


def cmd_suppress(args: argparse.Namespace) -> int:
    if getattr(args, "program", None) and getattr(args, "finding_id", None):
        return cmd_engagement_suppress(args)
    print(
        "error: shroodler suppress --program SLUG --id FINDING_ID --url URL --reason TEXT",
        file=sys.stderr,
    )
    return 2


def cmd_engagement_history(args: argparse.Namespace) -> int:
    from shroodler.engagement_history import format_run_history
    from shroodler.program import load

    state = load(str(args.program))
    print(format_run_history(state), end="")
    return 0


def cmd_engagement_diff(args: argparse.Namespace) -> int:
    from shroodler.engagement_history import diff_endpoints, format_endpoint_diff
    from shroodler.program import load

    state = load(str(args.program))
    diff = diff_endpoints(state.previous_endpoints or {}, state.endpoints)
    print(format_endpoint_diff(diff), end="")
    return 0


def _ticket_common(args: argparse.Namespace, *, close_resolved: bool) -> int:
    from shroodler.sla import load_ownership_rules
    from shroodler.suppress import load_suppressions
    from shroodler.tickets import run_ticket_command

    result = run_ticket_command(
        findings_path=args.findings,
        baseline_path=getattr(args, "baseline", None),
        state_path=getattr(args, "state", None) or ".shroodler-tickets.json",
        owners=load_ownership_rules(getattr(args, "owners", None)),
        suppressions=load_suppressions(getattr(args, "suppressions", None)),
        close_resolved=close_resolved,
        apply=bool(getattr(args, "apply", False)),
        repo=getattr(args, "repo", None),
    )
    text = json.dumps(result, indent=2) + "\n"
    _write(text, args.output)
    return 0


def cmd_ticket_file(args: argparse.Namespace) -> int:
    return _ticket_common(args, close_resolved=False)


def cmd_ticket_sync(args: argparse.Namespace) -> int:
    return _ticket_common(args, close_resolved=True)


def cmd_sla_apply(args: argparse.Namespace) -> int:
    from shroodler.history import default_history_dir
    from shroodler.sla import apply_sla, load_ownership_rules, wildcard_rules

    doc = load_json(args.scan_json)
    history_dir_arg = getattr(args, "history_dir", None)
    history_dir = Path(history_dir_arg) if history_dir_arg else default_history_dir()
    owners = load_ownership_rules(getattr(args, "owners", None))
    for rule in wildcard_rules(owners):
        print(
            f"warning: ownership rule id={rule['id']!r} url={rule['url']!r} "
            f"matches everything it applies to -- every matching finding will be "
            f"attributed to owner={rule['owner']!r}",
            file=sys.stderr,
        )
    result = apply_sla(doc, history_dir=history_dir, owners=owners)
    text = json.dumps(result, indent=2) + "\n"
    _write(text, args.output)
    if result["findings"] and not result["findings"][0].get("history_available", True):
        print(
            f"warning: no recorded scan history found for target "
            f"{doc.get('target', '')!r} in {history_dir} -- first_seen/age_days/"
            "sla_breached could NOT be evaluated for any finding (not the same as "
            "a clean result). Run `shroodler history record` after a scan to "
            "start tracking.",
            file=sys.stderr,
        )
    breached = [f for f in result["findings"] if f.get("sla_breached")]
    if getattr(args, "gate", False) and breached:
        for f in breached:
            print(
                f"SLA breached: {f['id']} @ {f['url']} "
                f"(age={f['age_days']}d, {f['severity']} -> {f['sla_severity']}, "
                f"owner={f['owner'] or '(unset)'})",
                file=sys.stderr,
            )
        return 1
    return 0


def cmd_self_scan(args: argparse.Namespace) -> int:
    from shroodler.self_scan import run_self_scan

    formats = list(getattr(args, "format", None) or []) or None
    result = run_self_scan(formats)
    text = json.dumps(result, indent=2) + "\n"
    _write(text, args.output)
    if result["findings"]:
        for f in result["findings"]:
            print(f"{f['severity']}: {f['id']} -- {f['description']}", file=sys.stderr)
        return 1
    print("self-scan clean: no report renderer echoed hostile input unescaped")
    return 0


def cmd_attack_path(args: argparse.Namespace) -> int:
    from shroodler.attack_path import build_attack_path, render_attack_path_markdown

    doc = load_json(args.findings)
    report = build_attack_path(doc)
    fmt = getattr(args, "format", "json") or "json"
    text = (
        render_attack_path_markdown(report)
        if fmt == "markdown"
        else json.dumps(report, indent=2) + "\n"
    )
    _write(text, args.output)
    return 0


def cmd_cadence(args: argparse.Namespace) -> int:
    from shroodler.cadence import recommend, render_text

    rec = recommend(args.tier, url=args.url)
    if args.format == "json":
        text = json.dumps(rec, indent=2) + "\n"
    else:
        text = render_text(rec)
    _write(text, args.output)
    return 0


def cmd_triage(args: argparse.Namespace) -> int:
    from shroodler.triage import render_hosts, render_text, run_triage

    doc = run_triage(
        list(getattr(args, "targets", None) or []),
        discover=list(getattr(args, "discover", None) or []),
        allow_external=bool(getattr(args, "allow_external", False)),
        no_active=bool(getattr(args, "no_active", False)),
        concurrency=getattr(args, "concurrency", None),
        rate=getattr(args, "rate", None),
        timeout=float(getattr(args, "timeout", 8.0) or 8.0),
        proxy=getattr(args, "proxy", None),
        user_agent=getattr(args, "user_agent", None),
        headers=list(getattr(args, "header", None) or []),
    )
    fmt = getattr(args, "format", "text") or "text"
    if fmt == "json":
        text = json.dumps(doc, indent=2) + "\n"
    elif fmt == "hosts":
        text = render_hosts(doc)
    else:
        text = render_text(doc)
    _write(text, args.output)
    hosts_out = getattr(args, "hosts_out", None)
    if hosts_out:
        Path(hosts_out).write_text(render_hosts(doc), encoding="utf-8")
    hosts = doc.get("hosts") or []
    if not hosts:
        return 1
    if doc.get("skipped_external") and doc["skipped_external"] == len(hosts):
        print(
            "error: every host was skipped as non-local; pass --allow-external "
            "to probe remote hosts you are authorized to test",
            file=sys.stderr,
        )
        return 1
    return 0


def cmd_triage_findings(args: argparse.Namespace) -> int:
    from shroodler.pentest_report import format_submit
    from shroodler.triage_engine import (
        findings_from_doc,
        format_text_table,
        result_to_dict,
        triage_findings,
    )

    doc = load_json(args.state_file)
    findings = findings_from_doc(doc)
    min_score = int(getattr(args, "min_score", 50) or 50)
    min_conf = int(getattr(args, "min_confidence", 65) or 65)
    results = triage_findings(
        findings,
        min_exploitability=min_score,
        min_confidence=min_conf,
    )
    fmt = getattr(args, "format", "text") or "text"
    if fmt == "json":
        text = json.dumps([result_to_dict(item) for item in results], indent=2) + "\n"
    elif fmt == "submit":
        text = format_submit(
            findings,
            min_exploitability=min_score,
            min_confidence=min_conf,
        )
    else:
        text = format_text_table(results)
    _write(text, args.output)
    return 0


def cmd_reverify(args: argparse.Namespace) -> int:
    from shroodler.reverify import reverify

    enforcer = None
    require_policy = getattr(args, "require_policy", False)
    policy_file = getattr(args, "policy_file", None)
    audit_log = getattr(args, "audit_log", None)
    run_payloads = not bool(getattr(args, "no_payloads", False))
    if run_payloads and (require_policy or policy_file or audit_log):
        from shroodler_guardrails.policy import (
            PolicyEnforcer,
            fetch_policy,
            origin_of,
            parse_policy,
        )

        if policy_file:
            manifest = json.loads(Path(policy_file).read_text(encoding="utf-8"))
            policy = parse_policy(manifest, origin=origin_of(args.url))
        else:
            policy = fetch_policy(args.url)
        enforcer = PolicyEnforcer(
            policy=policy,
            require_policy=require_policy,
            audit_path=Path(audit_log) if audit_log else None,
        )

    result = reverify(
        args.url,
        args.finding_id,
        mode=getattr(args, "mode", "static"),
        allow_external=bool(getattr(args, "allow_external", False)),
        run_payloads=run_payloads,
        enforcer=enforcer,
    )
    text = json.dumps(result, indent=2) + "\n"
    _write(text, args.output)
    for warning in result.get("warnings", []):
        print(f"warning: {warning}", file=sys.stderr)
    if result["verified_fixed"]:
        print(f"verified fixed: {args.finding_id} no longer present at {args.url}")
        return 0
    print(f"still present: {args.finding_id} at {args.url}", file=sys.stderr)
    return 1


def cmd_gen_regression_test(args: argparse.Namespace) -> int:
    from shroodler.gen_regression_test import render_regression_test
    from shroodler.reverify import reverify

    run_payloads = not bool(getattr(args, "no_payloads", False))
    result = reverify(
        args.url,
        args.finding_id,
        mode=getattr(args, "mode", "static"),
        allow_external=bool(getattr(args, "allow_external", False)),
        run_payloads=run_payloads,
    )
    if not result["verified_fixed"]:
        print(
            f"refusing to generate a regression test: {args.finding_id} is still "
            f"present at {args.url} -- fix it first, then regenerate",
            file=sys.stderr,
        )
        return 1
    warnings = result.get("warnings", [])
    if warnings and not getattr(args, "force", False):
        print(
            "refusing to generate a regression test: reverify's verified_fixed=true "
            "came with a warning about whether this re-scan could have actually "
            "caught a regression -- fix the underlying issue (see below) or pass "
            "--force to generate anyway:",
            file=sys.stderr,
        )
        for warning in warnings:
            print(f"  - {warning}", file=sys.stderr)
        return 1
    for warning in warnings:
        print(f"warning (forced past): {warning}", file=sys.stderr)
    text = render_regression_test(
        args.url,
        args.finding_id,
        mode=getattr(args, "mode", "static"),
        run_payloads=run_payloads,
        allow_external=bool(getattr(args, "allow_external", False)),
    )
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"wrote {args.output}")
    else:
        print(text, end="")
    return 0


def cmd_audit_verify(args: argparse.Namespace) -> int:
    from shroodler_guardrails.policy import verify_audit_log

    problems = verify_audit_log(Path(args.audit_log))
    if problems:
        for p in problems:
            print(p, file=sys.stderr)
        print(f"{len(problems)} problem(s) found in {args.audit_log}", file=sys.stderr)
        return 1
    print(f"audit log intact: {args.audit_log}")
    return 0


def cmd_proxy(args: argparse.Namespace) -> int:
    binary = find_proxy_bin()
    if binary is None:
        print(
            "shroodler-proxy not found. Run `make bins` or set SHROODLER_PROXY_BIN.",
            file=sys.stderr,
        )
        return 1
    forwarded = list(getattr(args, "proxy_args", None) or [])
    completed = subprocess.run([str(binary), *forwarded], check=False)
    return int(completed.returncode)


def cmd_version(_args: argparse.Namespace | None = None) -> int:
    print(f"shroodler {__version__}")
    return 0


def cmd_ask(args: argparse.Namespace) -> int:
    from shroodler.ask import answer

    scan = load_json(args.scan_json)
    older = load_json(args.since) if getattr(args, "since", None) else None
    result = answer(args.question, scan, older_scan=older)
    print(result.text)
    return 0


def cmd_mcp_server(args: argparse.Namespace) -> int:
    from shroodler_mcp.server import main as mcp_main

    argv: list[str] = []
    if getattr(args, "list_tools", False):
        argv.append("--list-tools")
    return mcp_main(argv)


def cmd_program_scope(args: argparse.Namespace) -> int:
    from shroodler.scope import load_scope, save_scope

    slug = str(args.program)
    scope = load_scope(slug)
    includes = [str(item) for item in (getattr(args, "include", None) or []) if str(item)]
    excludes = [str(item) for item in (getattr(args, "exclude", None) or []) if str(item)]
    if includes:
        existing = [str(item) for item in (scope.get("include") or []) if str(item)]
        scope["include"] = list(dict.fromkeys(existing + includes))
    if excludes:
        existing = [str(item) for item in (scope.get("exclude") or []) if str(item)]
        scope["exclude"] = list(dict.fromkeys(existing + excludes))
    scope.setdefault("allow_subdomains", True)
    path = save_scope(slug, scope)
    print(json.dumps({"path": str(path), **scope}))
    return 0


def cmd_dedup(args: argparse.Namespace) -> int:
    from shroodler.dedup import deduplicate

    doc = load_json(args.findings)
    if isinstance(doc, list):
        payload: object = deduplicate(doc)
    else:
        payload = dict(doc)
        payload["findings"] = deduplicate(list(doc.get("findings") or []))
    text = json.dumps(payload, indent=2) + "\n"
    _write(text, getattr(args, "output", None))
    return 0


def cmd_ci_template(args: argparse.Namespace) -> int:
    from shroodler.ci_templates import render_ci_template

    text = render_ci_template(
        str(args.platform),
        program=str(getattr(args, "program", None) or ""),
        target=str(getattr(args, "target", None) or ""),
    )
    if not text.endswith("\n"):
        text += "\n"
    print(text, end="")
    return 0


