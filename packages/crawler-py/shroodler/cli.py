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
from shroodler.config import load_rc
from shroodler.crawler import crawl_url
from shroodler.diffcmd import diff_outcome, load_json
from shroodler.robots import DEFAULT_UA
from shroodler.suppress import filter_findings, load_suppressions
from shroodler.validate import validate_crawl

_REPO_ROOT = Path(__file__).resolve().parents[3]

# `--profile NAME` bundles for `crawl`. Applied as parser defaults (see
# _apply_profile) so an explicit flag on the command line still wins over
# the profile's value -- these are starting points, not hard overrides.
PROFILES: dict[str, dict[str, object]] = {
    "safe": {
        "depth": 3,
        "max_pages": 100,
        "max_time": 60.0,
        "check_rate_limit": False,
    },
    "balanced": {
        "depth": 5,
        "max_pages": 400,
        "max_time": 0.0,
        "check_rate_limit": False,
    },
    "aggressive": {
        "depth": -1,
        "max_pages": 2000,
        "max_time": 0.0,
        "check_rate_limit": True,
    },
}


def _as_str_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    return []


def _progress(pages: int, current: str) -> None:
    print(f"PROGRESS pages={pages} current={current}", flush=True)


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
    result = crawl_url(
        args.url,
        mode=args.mode,
        depth=depth,
        ignore_robots=args.ignore_robots,
        allow_external=args.allow_external,
        max_pages=max_pages,
        max_time=max_time,
        progress=_progress,
        cookies=cookies,
        headers=headers,
        cookie_jar=getattr(args, "cookie_jar", None),
        storage_state=getattr(args, "storage_state", None),
        login_recipe=getattr(args, "login_recipe", None),
        proxy=getattr(args, "proxy", None),
        extra_seeds=extra_seeds,
        no_sitemap=bool(getattr(args, "no_sitemap", False)),
        check_rate_limit=bool(getattr(args, "check_rate_limit", False)),
        check_idor=bool(getattr(args, "check_idor", False)),
        plugins=list(getattr(args, "plugin", None) or []),
        exclude_paths=list(getattr(args, "exclude_path", None) or []),
        gql_field_names=_gql_field_names(args),
        from_capture=getattr(args, "from_capture", None),
        **({"user_agent": args.user_agent} if getattr(args, "user_agent", None) else {}),
    )
    doc = result.to_dict()
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


def cmd_compare_engines(args: argparse.Namespace) -> int:
    from shroodler.compare_engines import merge_engine_results

    py_doc = load_json(args.python_crawl_json)
    go_doc = load_json(args.go_crawl_json)
    merged = merge_engine_results(py_doc, go_doc)
    text = json.dumps(merged, indent=2) + "\n"
    _write(text, args.output)
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


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="shroodler",
        description=(
            "Shroodler command-line toolkit: crawl a target, render reports, "
            "diff baselines, run payload packs, or drive the intercepting proxy. "
            "Local targets (127.0.0.1/localhost) are crawled by default; pass "
            "--allow-external to scan a remote target you're authorized to test."
        ),
        epilog=(
            "Examples:\n"
            "  shroodler crawl http://127.0.0.1:8081 -o out.json\n"
            "  shroodler crawl https://example.com --allow-external -o out.json\n"
            "  shroodler crawl http://127.0.0.1:8081 --profile aggressive -o out.json\n"
            "  shroodler report out.json --format html -o out.html\n"
            "  shroodler payload out.json -o hits.json\n"
            "  shroodler proxy start --record /tmp/sess.jsonl\n"
            "Desktop GUI is optional; this CLI is the full product surface."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-V", "--version", action="store_true", help="Print version and exit")
    p.add_argument(
        "--debug",
        action="store_true",
        help="Print full tracebacks on error instead of a one-line message",
    )
    sub = p.add_subparsers(dest="command", required=False)

    crawl = sub.add_parser("crawl", help="Crawl a target URL")
    crawl.add_argument("url")
    crawl.add_argument(
        "--profile",
        choices=sorted(PROFILES),
        help="Apply a bundle of sane defaults (depth/max-pages/max-time/"
        "check-rate-limit) for a scan style; individual flags on the command "
        "line still override the profile's values. See PROFILES in cli.py.",
    )
    crawl.add_argument("--mode", choices=["static", "headless"], default="static")
    crawl.add_argument("--depth", type=int, default=5, help="Max depth; -1 for unbounded")
    crawl.add_argument(
        "--max-pages",
        type=int,
        default=400,
        help="Stop starting new fetches after this many pages (default 400)",
    )
    crawl.add_argument(
        "--max-time",
        type=float,
        default=0,
        help="Wall-clock budget in seconds; 0 means no time limit",
    )
    crawl.add_argument("--output", "-o")
    crawl.add_argument(
        "--format",
        choices=["json", "html", "csv", "sarif", "junit"],
        default="json",
    )
    crawl.add_argument("--ignore-robots", action="store_true")
    crawl.add_argument(
        "--no-sitemap",
        action="store_true",
        help="Skip robots.txt Sitemap: and /sitemap.xml discovery seeds",
    )
    crawl.add_argument(
        "--allow-external",
        action="store_true",
        help="Allow crawling a non-local target (any host outside "
        "127.0.0.1/localhost); off by default",
    )
    crawl.add_argument(
        "--check-rate-limit",
        action="store_true",
        help="Fire repeated bad-credential requests at discovered login/auth "
        "forms to check for missing rate limiting. Off by default: this "
        "sends real repeated requests with real consequences (lockouts, "
        "alerting) -- only use against targets you're authorized to load-test. "
        "Pass --no-check-rate-limit to force it off even under --profile aggressive.",
    )
    crawl.add_argument(
        "--no-check-rate-limit",
        dest="check_rate_limit",
        action="store_false",
        help=argparse.SUPPRESS,
    )
    crawl.add_argument(
        "--check-idor",
        action="store_true",
        help="For crawled URLs with a purely-numeric path segment or query "
        "value, replay adjacent IDs (n-1, n+1) using the crawl's own "
        "session and flag ones that return a same-shaped JSON object "
        "(a lead worth manually confirming, not a proven IDOR -- a "
        "single session can't tell whether the adjacent ID belongs to a "
        "different account or is just another of the current account's "
        "own sequentially-allocated records; expect noise on targets "
        "where that's common). Off by default: this makes up to 4 real "
        "extra GET requests per candidate (up to 25 candidates) for IDs "
        "that were not organically discovered -- potentially reading "
        "another user's data, and a GET is not guaranteed side-effect-free "
        "on every API (e.g. marking something as viewed) -- only use "
        "against targets you're authorized to test this way. JSON API "
        "responses only; HTML/other content types are skipped.",
    )
    crawl.add_argument(
        "--header",
        action="append",
        default=[],
        help="Extra request header 'Name: value' (repeatable). Sent on every crawl fetch.",
    )
    crawl.add_argument(
        "--cookie",
        action="append",
        default=[],
        help="Cookie name=value (repeatable). Applied before the crawl.",
    )
    crawl.add_argument(
        "--cookie-jar",
        help="Netscape cookies.txt, JSON cookie list, or Playwright storageState",
    )
    crawl.add_argument(
        "--storage-state",
        help="Playwright storageState JSON (cookies only)",
    )
    crawl.add_argument(
        "--login-recipe",
        help="JSON {url, method, fields} posted once before crawling (merges hidden "
        "fields). If a later fetch returns 401 or a login redirect, the recipe is "
        "re-run once and that URL retried.",
    )
    crawl.add_argument(
        "--user-agent",
        help="Override the User-Agent sent on every crawl request (default: "
        f"{DEFAULT_UA!r}). Some targets serve different content, or block "
        "requests entirely, based on User-Agent.",
    )
    crawl.add_argument("--proxy", help="HTTP proxy URL, e.g. http://127.0.0.1:8888")
    crawl.add_argument(
        "--seed",
        action="append",
        default=[],
        help="Extra same-origin URL to enqueue (repeatable)",
    )
    crawl.add_argument(
        "--exclude-path",
        action="append",
        default=[],
        metavar="PREFIX",
        help="Skip any URL whose path starts with PREFIX (repeatable). "
        "Example: --exclude-path /markets/ to avoid crawling the entire "
        "markets section when you want to focus on authenticated paths.",
    )
    crawl.add_argument(
        "--spec",
        action="append",
        default=[],
        metavar="FILE",
        help="Local OpenAPI/Swagger or Postman collection; enqueue same-origin "
        "paths as extra crawl seeds (repeatable)",
    )
    crawl.add_argument("--seed-from", help="HAR or proxy session JSONL; enqueue captured same-origin URLs")
    crawl.add_argument(
        "--from-capture",
        metavar="FILE",
        help="HAR or proxy JSONL: ingest captured pages (no re-fetch) and live-crawl "
        "only the links/API seeds the recording mentioned. Use with --proxy when "
        "the HTML crawler is WAF-blocked.",
    )
    crawl.add_argument(
        "--cookies-from",
        help="HAR or proxy session JSONL; Cookie header from captured Set-Cookie / Cookie",
    )
    crawl.add_argument(
        "--gql-schema",
        action="append",
        default=[],
        metavar="FILE",
        help="Clairvoyance / GraphQL introspection JSON; Query field names are "
        "recorded on discovered GraphQL endpoints so authz-diff can replay them "
        "when live introspection is blocked (repeatable)",
    )
    crawl.add_argument(
        "--gql-wordlist",
        action="append",
        default=[],
        metavar="FILE",
        help="Plain field-name wordlist (one name per line) used the same way as "
        "--gql-schema when introspection is disabled (repeatable)",
    )
    crawl.add_argument(
        "--plugin",
        action="append",
        default=[],
        metavar="PATH",
        help="Plugin dir or file (payload packs, secret rules, Python checks). "
        "Repeatable. Also reads $SHROODLER_PLUGIN_PATH.",
    )
    crawl.set_defaults(func=cmd_crawl)

    diff = sub.add_parser("diff", help="Compare crawl JSON to expected_findings.json")
    diff.add_argument("findings")
    diff.add_argument("expected")
    diff.add_argument("--pages-only", action="store_true")
    diff.add_argument(
        "--gate",
        action="store_true",
        help="CI mode: fail on findings not in the baseline; resolved findings do not fail",
    )
    diff.add_argument(
        "--suppressions",
        default=None,
        help="Suppression rules JSON/YAML (default: .shroodlerignore if present). Each rule "
        "is {id, url} (glob-matched, '*' for either); optional 'expires' (YYYY-MM-DD) makes "
        "a rule stop suppressing once passed -- diff warns (not fails) when a rule has "
        "expired, since the finding it hid is now enforced again. Optional 'owner' is "
        "carried through for humans/tooling; this command doesn't use it.",
    )
    diff.add_argument(
        "--format", choices=["text", "junit", "sarif", "github-annotations"], default="text"
    )
    diff.add_argument("--output", "-o")
    diff.add_argument(
        "--source-root",
        metavar="DIR",
        help="Attribute each new (--gate) finding's URL to a source file/line by grepping "
        "route-registration patterns under this directory, and (if it's a git repo) the "
        "commit that last touched that line -- 'this finding looks introduced by "
        "routes/export.py:44'. Best-effort/heuristic, not a real router analysis.",
    )
    diff.set_defaults(func=cmd_diff)

    report = sub.add_parser(
        "report", help="Render findings JSON as HTML, CSV, SARIF, JUnit, or Markdown"
    )
    report.add_argument("findings")
    report.add_argument(
        "--format",
        choices=["html", "csv", "json", "sarif", "junit", "md", "markdown"],
        default="html",
    )
    report.add_argument("--output", "-o")
    report.add_argument("--suppressions", default=None)
    report.add_argument(
        "--merge-sarif",
        action="append",
        default=[],
        metavar="FILE",
        help="Fold an external SARIF 2.x file (Semgrep, CodeQL, Slither, ...) into "
        "this report's findings before rendering. Dedupes by id+url against "
        "findings already in the crawl JSON. Repeatable.",
    )
    report.set_defaults(func=cmd_report)

    baseline = sub.add_parser(
        "baseline",
        help="Write expected_findings.json from a scan",
        description=(
            "Map pages → expected_pages, forms → expected_forms, findings → "
            "expected_findings (id + url path). expected_not_found is left empty — "
            "add negatives by hand; this command does not invent them."
        ),
    )
    baseline.add_argument("findings")
    baseline.add_argument("--output", "-o")
    baseline.add_argument("--name", default=None)
    baseline.add_argument("--suppressions", default=None)
    baseline.set_defaults(func=cmd_baseline)

    expected = sub.add_parser(
        "expected",
        help="Write expected_findings.json from a scan (alias of baseline)",
        description=(
            "Map pages → expected_pages, forms → expected_forms, findings → "
            "expected_findings (id + url path). expected_not_found is left empty — "
            "add negatives by hand; this command does not invent them."
        ),
    )
    expected.add_argument("findings")
    expected.add_argument("--output", "-o")
    expected.add_argument("--name", default=None)
    expected.add_argument("--suppressions", default=None)
    expected.set_defaults(func=cmd_baseline)

    ingest = sub.add_parser(
        "ingest-sessions",
        help="Turn captured proxy JSONL (or a HAR) into findings",
    )
    ingest.add_argument("sessions")
    ingest.add_argument("--target", default=None)
    ingest.add_argument("--output", "-o")
    ingest.add_argument(
        "--allow-external",
        action="store_true",
        help="Allow ingesting sessions captured against a non-local target; off by default",
    )
    ingest.set_defaults(func=cmd_ingest)

    ingest_har = sub.add_parser(
        "ingest-har",
        help="Turn a Burp/mitmproxy/Caido/DevTools HAR into crawl JSON",
        description=(
            "Accept a HAR 1.2 export as crawl seeds: each HTTP entry becomes a "
            "Page record (URL, status, forms, params) plus passive findings from "
            "the captured bodies. Same output shape as ingest-sessions / crawl, "
            "so authz-diff and payload can consume it. Does not re-fetch the "
            "target. ingest-sessions also auto-detects HAR; this command is the "
            "named path for browser/Burp exports."
        ),
    )
    ingest_har.add_argument("sessions", help="HAR 1.2 file (Burp, mitmproxy, Caido, DevTools)")
    ingest_har.add_argument("--target", default=None)
    ingest_har.add_argument("--output", "-o")
    ingest_har.add_argument(
        "--allow-external",
        action="store_true",
        help="Allow ingesting a HAR captured against a non-local target; off by default",
    )
    ingest_har.set_defaults(func=cmd_ingest)

    tokens = sub.add_parser(
        "tokens",
        help="Analyze reset/verification token predictability from captured proxy JSONL",
    )
    tokens.add_argument(
        "sessions",
        help="Recorded proxy session JSONL (the same format --cookies-from/"
        "--seed-from/ingest-sessions consume). A token is normally delivered "
        "out-of-band (email/SMS); this only sees one if a tester's browser, "
        "routed through the recording proxy, actually visited the reset/"
        "verification link -- capture the same flow multiple times (e.g. "
        "request several password resets) to get more than one sample, "
        "since only 2+ samples let this test for a sequential/low-entropy "
        "generation pattern rather than a weaker length-only estimate.",
    )
    tokens.add_argument("--output", "-o")
    tokens.set_defaults(func=cmd_tokens)

    cadence = sub.add_parser(
        "cadence",
        help="Print recommended crawl/payload flags for a PR, nightly, or weekly scan",
        description=(
            "Packaging for the existing profiles: which flags to use on a PR "
            "(passive/safe), nightly (balanced + payload), or weekly "
            "(aggressive + adaptive payload). Prints commands; does not scan."
        ),
    )
    cadence.add_argument(
        "--tier",
        required=True,
        choices=["pr", "nightly", "weekly"],
        help="Which cadence slot to print flags for",
    )
    cadence.add_argument(
        "--url",
        default="http://127.0.0.1:8081",
        help="Placeholder target URL in the printed command (default http://127.0.0.1:8081)",
    )
    cadence.add_argument("--format", choices=["text", "json"], default="text")
    cadence.add_argument("--output", "-o")
    cadence.set_defaults(func=cmd_cadence)

    from shroodler.triage import (
        DEFAULT_CONCURRENCY,
        DEFAULT_PROXY_CONCURRENCY,
        DEFAULT_RATE_RPS,
        MAX_CONCURRENCY,
        MAX_RATE_RPS,
    )

    triage = sub.add_parser(
        "triage",
        help="Classify a host list (dead / redirect-alias / WAF / SSO / live) "
        "before spending crawl budget",
        description=(
            "A fast, low-touch pre-crawl pass: passive Certificate Transparency "
            "discovery, DNS/CNAME analysis, and one gentle HTTP probe per live "
            "host. It classifies; it does not crawl or fire payloads. Concurrency "
            "and request rate are bounded and clamped (never an unbounded fan-out); "
            "a local egress proxy is detected and stays under a lower connection "
            "ceiling; a WAF challenge or 429 pauses the rest of that zone; "
            "identifying User-Agent and per-program required headers are supported. "
            "Local-only by default."
        ),
    )
    triage.add_argument(
        "targets",
        nargs="*",
        help="Hostnames, URLs, and/or a file of them (one per line). "
        "A *.apex wildcard is treated as a --discover seed.",
    )
    triage.add_argument(
        "--discover",
        action="append",
        default=[],
        metavar="APEX",
        help="Expand this apex via Certificate Transparency (crt.sh) — contacts "
        "CT logs, not the target. Repeatable. Requires --allow-external.",
    )
    triage.add_argument(
        "--no-active",
        action="store_true",
        help="Skip the HTTP classification probe; DNS/CT only",
    )
    triage.add_argument(
        "--allow-external",
        action="store_true",
        help="Allow DNS/HTTP (and CT discovery) against non-local hosts; off by default",
    )
    triage.add_argument(
        "--concurrency",
        type=int,
        default=None,
        help=f"Max parallel probes (default {DEFAULT_CONCURRENCY}, "
        f"{DEFAULT_PROXY_CONCURRENCY} when a proxy is detected; clamped at "
        f"{MAX_CONCURRENCY})",
    )
    triage.add_argument(
        "--rate",
        type=float,
        default=None,
        metavar="RPS",
        help=f"Global HTTP requests/second cap (default {DEFAULT_RATE_RPS}; "
        f"clamped at {MAX_RATE_RPS})",
    )
    triage.add_argument(
        "--timeout",
        type=float,
        default=8.0,
        help="Per-request timeout in seconds (default 8)",
    )
    triage.add_argument("--proxy", help="HTTP proxy URL (also honors HTTP_PROXY/HTTPS_PROXY)")
    triage.add_argument("--user-agent", help="Identifying User-Agent for every probe")
    triage.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="'Name: value'",
        help="Required custom header (repeatable), e.g. Bugcrowd: <uuid>",
    )
    triage.add_argument("--output", "-o")
    triage.add_argument(
        "--format",
        choices=["text", "json", "hosts"],
        default="text",
        help="text table (default), json, or a crawl-ready host list",
    )
    triage.add_argument(
        "--hosts-out",
        metavar="FILE",
        help="Also write the worth-crawling URL list (same as --format hosts) to FILE",
    )
    triage.set_defaults(func=cmd_triage)

    payload = sub.add_parser(
        "payload",
        help="Run YAML payload packs (SQLi/XSS/SSTI/path-traversal/SSRF/"
        "open-redirect) against crawl JSON",
    )
    payload.add_argument("crawl_json")
    payload.add_argument("--output", "-o")
    payload.add_argument(
        "--pack",
        action="append",
        default=[],
        metavar="PATH",
        help="Extra YAML pack file or directory (repeatable)",
    )
    payload.add_argument(
        "--plugin",
        action="append",
        default=[],
        metavar="PATH",
        help="Plugin dir or file supplying extra payload packs. Repeatable. "
        "Also reads $SHROODLER_PLUGIN_PATH.",
    )
    payload.add_argument(
        "--allow-external",
        action="store_true",
        help="Allow sending active payloads to non-local targets. "
        "Only use against hosts you are authorized to test.",
    )
    payload.add_argument(
        "--oob-host",
        metavar="HOST",
        help="Your own out-of-band collaborator-style server (self-hosted "
        "Interactsh, an oast.* instance, or any host you control that logs "
        "incoming requests). A fresh random subdomain of it is used as "
        "{{MARKER_HOST}} in payloads each run. Shroodler cannot poll your "
        "server for you -- for 'blind' packs, check its logs afterward for "
        "the token printed in the output's oob_probes list.",
    )
    payload.add_argument(
        "--require-policy",
        action="store_true",
        help="Refuse to run unless the target publishes a "
        ".well-known/scan-policy.json consent manifest.",
    )
    payload.add_argument(
        "--policy-file",
        metavar="PATH",
        help="Use a local scan-policy.json instead of fetching one from the target.",
    )
    payload.add_argument(
        "--audit-log",
        metavar="PATH",
        help="Append a JSONL audit trail of every active request the guardrail "
        "allowed or blocked. Not implied by --require-policy/--policy-file alone -- "
        "pass this explicitly to get a durable record on disk.",
    )
    payload.add_argument(
        "--adaptive",
        action="store_true",
        help="On a baseline miss, retry once with an adapted payload instead of "
        "giving up (SHROODLER_PAYLOAD_MUTATE_CMD if set, else a built-in mutator); "
        "never reports a mutated match at confidence=confirmed.",
    )
    payload.add_argument(
        "--no-csrf",
        action="store_true",
        help="Do not harvest or attach CSRF tokens on write methods",
    )
    payload.set_defaults(func=cmd_payload)

    nuclei = sub.add_parser(
        "nuclei-ingest",
        help="Convert local Nuclei HTTP YAML templates into a payload pack",
        description=(
            "A loader, not a CVE library: converts Nuclei HTTP templates you "
            "already have on disk into the YAML list `payload --pack` consumes. "
            "`payload --pack` also auto-detects a Nuclei-shaped file. Does not "
            "download templates."
        ),
    )
    nuclei.add_argument(
        "templates",
        nargs="+",
        help="Local Nuclei YAML template file(s)",
    )
    nuclei.add_argument("--output", "-o", help="Write converted pack YAML (default stdout)")
    nuclei.set_defaults(func=cmd_nuclei_ingest)

    slither = sub.add_parser(
        "slither-ingest",
        help="Convert a local Slither JSON report into Shroodler findings",
        description=(
            "A loader, not an EVM analyzer: translates Slither JSON you already "
            "have on disk into a crawl-shaped findings document `report` / `diff` "
            "can consume. Does not run Slither or vendor its detectors."
        ),
    )
    slither.add_argument("report", help="Slither --json output file")
    slither.add_argument(
        "--target",
        default=None,
        help="Override the document target (default: first finding's file path)",
    )
    slither.add_argument("--output", "-o")
    slither.set_defaults(func=cmd_slither_ingest)

    authz = sub.add_parser(
        "authz-diff",
        help="Replay a privileged crawl's pages under a second (lower-priv) "
        "session to find broken access control / IDOR candidates",
        description=(
            "Takes a crawl JSON produced under one session (e.g. an admin "
            "account) and re-requests every page URL in it using a second "
            "session's --cookie/--header. A URL still reachable under the "
            "lower-privilege session is flagged; if it was also denied "
            "anonymously, that's a strong broken-access-control signal."
        ),
    )
    authz.add_argument("higher_crawl_json")
    authz.add_argument("--output", "-o")
    authz.add_argument(
        "--cookie",
        action="append",
        default=[],
        metavar="name=value",
        help="Cookie for the lower-privilege session to replay with (repeatable)",
    )
    authz.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="'Name: value'",
        help="Extra header for the lower-privilege session, e.g. an "
        "Authorization bearer token (repeatable)",
    )
    authz.add_argument(
        "--no-anon-check",
        action="store_true",
        help="Skip the anonymous control request; report every URL the lower-priv "
        "session can reach instead of only ones also denied anonymously",
    )
    authz.add_argument(
        "--allow-external",
        action="store_true",
        help="Allow replaying against a non-local target; off by default",
    )
    authz.add_argument(
        "--require-policy",
        action="store_true",
        help="Refuse to run unless the target publishes a "
        ".well-known/scan-policy.json consent manifest.",
    )
    authz.add_argument(
        "--policy-file",
        metavar="PATH",
        help="Use a local scan-policy.json instead of fetching one from the target.",
    )
    authz.add_argument(
        "--audit-log",
        metavar="PATH",
        help="Append a JSONL audit trail of every active request the guardrail "
        "allowed or blocked.",
    )
    authz.add_argument(
        "--higher-priv-marker",
        action="append",
        default=[],
        metavar="STRING",
        help="A string that uniquely identifies the higher-privilege account's own "
        "data (an email, username, or record value only it should see). If the "
        "lower-priv session's response contains it, the lead is upgraded to "
        "confidence=confirmed instead of just 'reachable' (repeatable).",
    )
    authz.add_argument(
        "--lower-priv-marker",
        action="append",
        default=[],
        metavar="STRING",
        help="A string identifying the LOWER-priv account's own data, to rule out a "
        "--higher-priv-marker match that's coincidentally also the requester's own "
        "identity rather than the other account's (repeatable).",
    )
    authz.add_argument(
        "--require-identity-confirmation",
        action="store_true",
        help="Drop a lead entirely instead of reporting it at lower confidence when "
        "no --higher-priv-marker was found in the response.",
    )
    authz.add_argument(
        "--gql-schema",
        action="append",
        default=[],
        metavar="FILE",
        help="Clairvoyance / GraphQL introspection JSON; Query field names fed to "
        "replay_graphql_fields when live introspection is blocked (repeatable)",
    )
    authz.add_argument(
        "--gql-wordlist",
        action="append",
        default=[],
        metavar="FILE",
        help="Plain field-name wordlist (one name per line) used the same way as "
        "--gql-schema (repeatable)",
    )
    authz.set_defaults(func=cmd_authz_diff)

    peer = sub.add_parser(
        "peer-write",
        help="Replay known-object writes as a second session (not n±1 enum)",
        description=(
            "Replay captured POST/PUT/PATCH/DELETE requests against *known* "
            "object ids as a peer session. Each write is also sent to a "
            "nonsense id: the same 200 body as the fake id is dummy-success, "
            "not a finding. success:false is a write-failure. A peer 2xx that "
            "differs from the control is an IDOR lead; an owner re-read that "
            "changed is confirmation. Does not invent adjacent ids."
        ),
    )
    peer.add_argument(
        "playbook",
        nargs="?",
        default=None,
        help="JSON playbook with target + writes[{method,url,body,id_value,verify}]",
    )
    peer.add_argument("--output", "-o")
    peer.add_argument("--target", help="Override playbook target / infer from --from-sessions")
    peer.add_argument(
        "--from-sessions",
        metavar="PATH",
        help="HAR or proxy JSONL; extract writes that already name an object id",
    )
    peer.add_argument(
        "--only-id",
        metavar="ID",
        help="Only replay writes whose known object id equals this value",
    )
    peer.add_argument(
        "--owner-cookie",
        action="append",
        default=[],
        metavar="name=value",
        help="Owner session cookie for the verify re-read (repeatable)",
    )
    peer.add_argument(
        "--peer-cookie",
        action="append",
        default=[],
        metavar="name=value",
        help="Peer session cookie used for the write replay (repeatable)",
    )
    peer.add_argument(
        "--owner-cookies-from",
        metavar="PATH",
        help="Owner cookies from Playwright storageState, Netscape jar, HAR, or JSONL",
    )
    peer.add_argument(
        "--peer-cookies-from",
        metavar="PATH",
        help="Peer cookies from Playwright storageState, Netscape jar, HAR, or JSONL",
    )
    peer.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="'Name: value'",
        help="Extra header on peer (and owner verify) requests (repeatable)",
    )
    peer.add_argument(
        "--rate",
        type=float,
        default=1.0,
        help="Minimum seconds between live requests (default 1 = 1 req/s)",
    )
    peer.add_argument(
        "--nonsense-id",
        default="1",
        help="Control id substituted into the same write (default 1)",
    )
    peer.add_argument("--user-agent", help="Override User-Agent (suffix is still appended)")
    peer.add_argument(
        "--user-agent-suffix",
        help="Appended to User-Agent (e.g. Bugcrowd-handle)",
    )
    peer.add_argument(
        "--allow-external",
        action="store_true",
        help="Allow replaying against a non-local target; off by default",
    )
    peer.add_argument(
        "--require-policy",
        action="store_true",
        help="Refuse to run unless the target publishes a "
        ".well-known/scan-policy.json consent manifest.",
    )
    peer.add_argument(
        "--policy-file",
        metavar="PATH",
        help="Use a local scan-policy.json instead of fetching one from the target.",
    )
    peer.add_argument(
        "--audit-log",
        metavar="PATH",
        help="Append a JSONL audit trail of every active request the guardrail "
        "allowed or blocked.",
    )
    peer.add_argument(
        "--csrf-from",
        metavar="URL",
        help="GET this URL to harvest a CSRF token before each write "
        "(default: the write's origin)",
    )
    peer.add_argument(
        "--no-csrf",
        action="store_true",
        help="Do not harvest or attach CSRF tokens",
    )
    peer.add_argument(
        "--require-confirm",
        action="store_true",
        help="Only emit a finding when the owner re-read shows the object changed "
        "(default when both owner and peer jars are set)",
    )
    peer.add_argument(
        "--allow-unconfirmed",
        action="store_true",
        help="Emit probable leads even when both owner and peer jars are set "
        "(overrides the default two-jar confirm)",
    )
    peer.set_defaults(func=cmd_peer_write)

    session_export = sub.add_parser(
        "session-export",
        help="Write a Playwright storageState JSON from a browser or captured jar",
        description=(
            "Dump HttpOnly cookies a hunt can actually replay. Connect to Chrome "
            "via --cdp (launch with --remote-debugging-port=9222), or convert a "
            "HAR / proxy JSONL / Netscape jar / existing storageState. The output "
            "is the file --owner-cookies-from / --peer-cookies-from already accept."
        ),
    )
    session_export.add_argument(
        "--from",
        dest="source",
        metavar="PATH",
        help="HAR, proxy JSONL, Netscape cookies.txt, or storageState JSON",
    )
    session_export.add_argument(
        "--cdp",
        metavar="URL",
        help="Chrome DevTools URL, e.g. http://127.0.0.1:9222 (loopback only)",
    )
    session_export.add_argument(
        "--origin",
        default="",
        help="Absolute http(s) origin; only keep cookies for that host",
    )
    session_export.add_argument(
        "--cookie",
        action="append",
        default=[],
        metavar="name=value",
        help="Include this cookie (repeatable)",
    )
    session_export.add_argument(
        "--allow-external",
        action="store_true",
        help="Allow --cdp against a non-loopback DevTools URL",
    )
    session_export.add_argument("--output", "-o", help="Write storageState JSON (default stdout)")
    session_export.set_defaults(func=cmd_session_export)

    js_routes = sub.add_parser(
        "js-routes",
        help="Extract parameterized URL templates from a JS bundle",
        description=(
            "Mine {userId}/{collectionId}/{pk}, ${var}, :id, and <int:pk> "
            "route templates from webpack/SPA JS. Templates only — does not "
            "fetch or enumerate ids."
        ),
    )
    js_routes.add_argument("js_file", help="Local JavaScript file to scan")
    js_routes.add_argument("--output", "-o", help="Write routes JSON (default stdout)")
    js_routes.set_defaults(func=cmd_js_routes)

    paced = sub.add_parser(
        "paced-fetch",
        help="GET a URL list at a capped request rate (default 1 req/s)",
        description=(
            "Rate-limited GET/HEAD/OPTIONS for agent or Playwright loops. "
            "Does not solve captchas. Writes are refused — use peer-write."
        ),
    )
    paced.add_argument(
        "--url",
        action="append",
        default=[],
        metavar="URL",
        help="URL to fetch (repeatable)",
    )
    paced.add_argument(
        "--urls-file",
        metavar="PATH",
        help="Text file of URLs, one per line",
    )
    paced.add_argument("--output", "-o")
    paced.add_argument(
        "--method",
        default="GET",
        choices=["GET", "HEAD", "OPTIONS"],
        help="Safe method only (default GET)",
    )
    paced.add_argument(
        "--cookie",
        action="append",
        default=[],
        metavar="name=value",
        help="Cookie (repeatable)",
    )
    paced.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="'Name: value'",
        help="Extra header (repeatable)",
    )
    paced.add_argument(
        "--rate",
        type=float,
        default=1.0,
        help="Minimum seconds between requests (default 1)",
    )
    paced.add_argument("--user-agent")
    paced.add_argument("--user-agent-suffix")
    paced.add_argument(
        "--allow-external",
        action="store_true",
        help="Allow fetching a non-local target; off by default",
    )
    paced.add_argument(
        "--require-policy",
        action="store_true",
        help="Refuse to run unless the target publishes a "
        ".well-known/scan-policy.json consent manifest.",
    )
    paced.add_argument(
        "--policy-file",
        metavar="PATH",
        help="Use a local scan-policy.json instead of fetching one from the target.",
    )
    paced.add_argument(
        "--audit-log",
        metavar="PATH",
        help="Append a JSONL audit trail of every active request the guardrail "
        "allowed or blocked.",
    )
    paced.set_defaults(func=cmd_paced_fetch)

    proxy = sub.add_parser(
        "proxy",
        help="Forward to shroodler-proxy (start, ca, replay)",
    )
    proxy.add_argument(
        "proxy_args",
        nargs=argparse.REMAINDER,
        help="Arguments passed to shroodler-proxy",
    )
    proxy.set_defaults(func=cmd_proxy)

    history = sub.add_parser(
        "history",
        help="Record and list local scan history (for trend diffing over time)",
    )
    history_sub = history.add_subparsers(dest="history_command", required=True)
    hrecord = history_sub.add_parser(
        "record", help="Save a scan's findings JSON into local history"
    )
    hrecord.add_argument("findings")
    hrecord.add_argument("--label", help="Extra label appended to the stored scan's id")
    hrecord.add_argument(
        "--history-dir",
        help="Override the history directory (default ~/.shroodler/history "
        "or $SHROODLER_HISTORY_DIR)",
    )
    hrecord.set_defaults(func=cmd_history_record)
    hlist = history_sub.add_parser("list", help="List recorded scans")
    hlist.add_argument("--target", help="Only show scans for this exact target URL")
    hlist.add_argument("--format", choices=["text", "json"], default="text")
    hlist.add_argument("--history-dir")
    hlist.set_defaults(func=cmd_history_list)

    trend = sub.add_parser(
        "trend",
        help="Diff findings between two recorded (or arbitrary) scans",
        description=(
            "Unlike `diff` (which gates against a static checked-in baseline), "
            "`trend` compares any two scans -- typically two entries from "
            "`shroodler history list` -- and reports findings introduced and "
            "resolved between them."
        ),
    )
    trend.add_argument("older", help="Older scan: a history id, or a path to a findings JSON file")
    trend.add_argument("newer", help="Newer scan: a history id, or a path to a findings JSON file")
    trend.add_argument("--format", choices=["text", "json"], default="text")
    trend.add_argument("--output", "-o")
    trend.add_argument("--history-dir")
    trend.add_argument(
        "--suppressions",
        default=None,
        help="Same .shroodlerignore-style file `diff`/`baseline` take -- suppressed "
        "findings are excluded from both scans before diffing, so an accepted finding "
        "can't fail --gate-on-severity-increase.",
    )
    trend.add_argument(
        "--gate-on-severity-increase",
        action="store_true",
        help="Exit 1 if any finding present in both scans (same id+url, so not "
        "'introduced') has a worse severity in the newer scan than the older one -- "
        "catches a same-key regression that `diff --gate` can't see, since its "
        "static baseline never recorded a severity to compare against.",
    )
    trend.add_argument(
        "--gate-on-waf-coverage-drop",
        action="store_true",
        help="Exit 1 if the fraction of crawled pages showing a WAF/bot-mitigation "
        "challenge dropped by more than --waf-drop-threshold between the two scans "
        "-- 'my own protection silently got weaker' as a tracked regression, not "
        "just a quieter scan. Does NOT fail the build when the two scans crawled "
        "very different numbers of pages (see --gate-even-if-page-count-mismatch); "
        "the regression is still reported, just not gated on.",
    )
    trend.add_argument(
        "--waf-drop-threshold",
        type=float,
        default=0.2,
        metavar="FRACTION",
        help="Minimum absolute coverage drop (0.0-1.0, default 0.2 = 20 percentage "
        "points) to count as a regression.",
    )
    trend.add_argument(
        "--gate-even-if-page-count-mismatch",
        action="store_true",
        help="With --gate-on-waf-coverage-drop, fail the build even when the two "
        "scans' page counts differ by more than 2x (a low-confidence comparison by "
        "default).",
    )
    trend.set_defaults(func=cmd_trend)

    version = sub.add_parser("version", help="Print version")
    version.set_defaults(func=cmd_version)

    ask = sub.add_parser(
        "ask",
        help="Ask a question over a scan/report ('show critical findings', "
        "'what's new since', 'reachable without auth')",
    )
    ask.add_argument("question")
    ask.add_argument("scan_json")
    ask.add_argument(
        "--since",
        metavar="OLDER_SCAN_JSON",
        help="An older scan to compare against for 'new since'/'resolved' questions",
    )
    ask.set_defaults(func=cmd_ask)

    mcp_server = sub.add_parser(
        "mcp-server",
        help="Run the MCP server exposing Shroodler as agent tools over stdio",
        description=(
            "MCP (Model Context Protocol) server on stdio JSON-RPC 2.0. An MCP-"
            "speaking coding agent can call these tools without shelling out to "
            "the CLI:\n"
            "  scan_route          crawl one URL (optional active payloads)\n"
            "  check_idor          confirm or drop an IDOR lead with a second session\n"
            "  peer_write          replay known-object writes as a peer session\n"
            "  session_export      dump storageState from HAR/JSONL/CDP\n"
            "  extract_js_routes   mine {id} URL templates from a local JS file\n"
            "  paced_fetch         GET a short URL list at 1 req/s\n"
            "  reverify_fix        re-scan one route and report if a finding is gone\n"
            "  diff_since_baseline compare a scan to a checked-in baseline\n"
            "  explain_finding     static remediation guidance for a finding id\n"
            "Active tools require a scan-policy consent manifest by default. "
            "Pass --list-tools to print names, descriptions, and input schemas "
            "and exit, without starting the stdio loop."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    mcp_server.add_argument(
        "--list-tools",
        action="store_true",
        help="Print the tool catalog (name, description, input schema) and exit",
    )
    mcp_server.set_defaults(func=cmd_mcp_server)

    audit_verify = sub.add_parser(
        "audit-verify",
        help="Replay a guardrail --audit-log and confirm its hash chain is intact",
    )
    audit_verify.add_argument("audit_log")
    audit_verify.set_defaults(func=cmd_audit_verify)

    self_scan = sub.add_parser(
        "self-scan",
        help="Adversarial self-scan: fuzz the tool's own report renderers with "
        "hostile finding content, catching stored-XSS-via-echoed-payload-in-report",
        description=(
            "Renders synthetic findings whose free-text fields contain classic "
            "HTML/JS-injection payloads through every report format, and checks "
            "whether any renderer echoed the payload back UNESCAPED -- a report a "
            "human opens in a browser must never become an XSS delivery vector for "
            "content that originated from the scanned target's own responses."
        ),
    )
    self_scan.add_argument(
        "--format",
        action="append",
        choices=["html", "csv", "sarif", "junit", "markdown"],
        help="Limit to specific format(s) (repeatable); default checks all of them "
        "('json' is excluded -- it bypasses the template renderers entirely and "
        "isn't supposed to be HTML-escaped)",
    )
    self_scan.add_argument("--output", "-o")
    self_scan.set_defaults(func=cmd_self_scan)

    attack_path = sub.add_parser(
        "attack-path",
        help="Correlate findings with reachability + weak-token context into one report",
        description=(
            "Correlates every finding with its URL path-depth (a heuristic proxy "
            "for click-distance from the target root -- not a real link-graph "
            "traversal, since neither crawler engine persists one) and whether "
            "this same scan found evidence of a guessable session/reset token."
        ),
    )
    attack_path.add_argument("findings")
    attack_path.add_argument("--format", choices=["json", "markdown"], default="json")
    attack_path.add_argument("--output", "-o")
    attack_path.set_defaults(func=cmd_attack_path)

    reverify = sub.add_parser(
        "reverify",
        help="Re-scan one route and check whether a specific finding is now gone "
        "(closed-loop remediate-and-reverify)",
        description=(
            "Re-crawls exactly URL (and, unless --no-payloads, re-runs active "
            "payload packs against it), then reports whether FINDING_ID still "
            "appears there. Exits 0 with verified_fixed=true only when it's "
            "actually gone from a fresh scan -- not merely 'a patch was applied'. "
            "Intended to gate whether an agent's auto-remediation PR should open "
            "at all."
        ),
    )
    reverify.add_argument("url")
    reverify.add_argument("finding_id")
    reverify.add_argument("--mode", choices=["static", "headless"], default="static")
    reverify.add_argument("--allow-external", action="store_true")
    reverify.add_argument(
        "--no-payloads",
        action="store_true",
        help="Only re-run the passive crawl, skip active payload packs",
    )
    reverify.add_argument("--output", "-o")
    reverify.add_argument(
        "--require-policy",
        action="store_true",
        help="Refuse to run active payloads unless the target publishes a "
        "scan-policy consent manifest.",
    )
    reverify.add_argument("--policy-file", metavar="PATH")
    reverify.add_argument("--audit-log", metavar="PATH")
    reverify.set_defaults(func=cmd_reverify)

    gen_test = sub.add_parser(
        "gen-regression-test",
        help="Generate a pytest regression test from a confirmed-then-fixed finding",
        description=(
            "Runs the same check as `reverify`; only writes a regression test if "
            "the finding is confirmed gone. Refuses (exit 1, no file written) if "
            "the finding is still present -- this command never generates a test "
            "for something that isn't actually fixed yet."
        ),
    )
    gen_test.add_argument("url")
    gen_test.add_argument("finding_id")
    gen_test.add_argument("--mode", choices=["static", "headless"], default="static")
    gen_test.add_argument("--allow-external", action="store_true")
    gen_test.add_argument("--no-payloads", action="store_true")
    gen_test.add_argument("--output", "-o")
    gen_test.add_argument(
        "--force",
        action="store_true",
        help="Generate the test even if reverify's verified_fixed=true came with a "
        "warning (e.g. url has no query string, so a GET-parameter finding may not "
        "have actually been re-tested).",
    )
    gen_test.set_defaults(func=cmd_gen_regression_test)

    compare_engines = sub.add_parser(
        "compare-engines",
        help="Merge Python and Go crawl JSON, tagging each finding with which "
        "engine(s) reproduced it -- agreement as a confidence signal",
    )
    compare_engines.add_argument("python_crawl_json")
    compare_engines.add_argument("go_crawl_json")
    compare_engines.add_argument("--output", "-o")
    compare_engines.set_defaults(func=cmd_compare_engines)

    ticket = sub.add_parser(
        "ticket",
        help="File or sync GitHub issues from scan findings (dry-run by default)",
    )
    ticket_sub = ticket.add_subparsers(dest="ticket_command", required=True)

    def _ticket_flags(p: argparse.ArgumentParser) -> None:
        p.add_argument("findings", help="Crawl / findings JSON")
        p.add_argument(
            "--baseline",
            help="expected_findings.json; only findings that would fail "
            "diff --gate are filed. Without this, every visible finding is a candidate.",
        )
        p.add_argument(
            "--state",
            default=".shroodler-tickets.json",
            help="Local JSON mapping finding keys to issue numbers "
            "(default .shroodler-tickets.json)",
        )
        p.add_argument(
            "--owners",
            help="Ownership-rules file; matching owner is assigned on the issue",
        )
        p.add_argument("--suppressions", default=None)
        p.add_argument("--repo", help="GitHub owner/name passed to gh --repo")
        p.add_argument(
            "--apply",
            action="store_true",
            help="Actually call `gh issue create`/`close` and write --state. "
            "Without this flag the command is a dry-run.",
        )
        p.add_argument("--output", "-o")

    tfile = ticket_sub.add_parser(
        "file",
        help="Open issues for new findings (deduped by id+path)",
        description=(
            "Turns findings that would fail `diff --gate` into GitHub issues, "
            "deduped by the same (id, path) key. Dry-run by default; pass "
            "--apply to invoke `gh`. Never talks to GitHub without --apply."
        ),
    )
    _ticket_flags(tfile)
    tfile.set_defaults(func=cmd_ticket_file)

    tsync = ticket_sub.add_parser(
        "sync",
        help="File new findings and close tickets whose findings are gone",
        description=(
            "Like `ticket file`, then closes issues recorded in --state whose "
            "finding key is no longer in the current scan. Dry-run by default."
        ),
    )
    _ticket_flags(tsync)
    tsync.set_defaults(func=cmd_ticket_sync)

    sla = sub.add_parser(
        "sla",
        help="Attach ownership + SLA-escalated severity to findings, using recorded history",
    )
    sla_sub = sla.add_subparsers(dest="sla_command", required=True)
    sla_apply = sla_sub.add_parser(
        "apply",
        help="Resolve owner + first-seen age + SLA-escalated severity per finding",
        description=(
            "Looks up each finding's earliest appearance in recorded scan "
            "history (see `history record`) and, once its age exceeds the "
            "SLA budget for its severity (critical=2d, high=7d, medium=30d, "
            "low=90d, info=180d by default), escalates it one severity level "
            "in a new `sla_severity` field. Also resolves `owner` from an "
            "ownership-rules file (same id/url glob format as "
            ".shroodlerignore)."
        ),
    )
    sla_apply.add_argument("scan_json")
    sla_apply.add_argument("--output", "-o")
    sla_apply.add_argument(
        "--history-dir",
        help="Override the history directory (default ~/.shroodler/history "
        "or $SHROODLER_HISTORY_DIR)",
    )
    sla_apply.add_argument(
        "--owners",
        help="Ownership-rules file (id/url glob rows, each with an 'owner' field)",
    )
    sla_apply.add_argument(
        "--gate",
        action="store_true",
        help="Exit 1 and list every SLA-breached finding on stderr",
    )
    sla_apply.set_defaults(func=cmd_sla_apply)

    suppress = sub.add_parser(
        "suppress",
        help="Work with suppression rules (.shroodlerignore) beyond diff/report/baseline",
    )
    suppress_sub = suppress.add_subparsers(dest="suppress_command", required=True)
    suppress_expiring = suppress_sub.add_parser(
        "expiring",
        help="List suppression rules expiring soon, or render a PR body for a scheduled job",
        description=(
            "A suppression rule aging past its `expires` date only ever "
            "warns once it's already expired (see the warning `diff` and "
            "other commands print). This looks the other direction: rules "
            "expiring within --days, so a scheduled CI job can open a PR "
            "nudging someone to extend-with-justification or remove one "
            "before it lapses, rather than someone noticing after the fact."
        ),
    )
    suppress_expiring.add_argument(
        "--days", type=int, default=14, help="Expiry horizon in days (default 14)"
    )
    suppress_expiring.add_argument("--suppressions", default=None)
    suppress_expiring.add_argument(
        "--format", choices=["text", "json", "github-pr-body"], default="text"
    )
    suppress_expiring.add_argument("--output", "-o")
    suppress_expiring.add_argument(
        "--gate", action="store_true", help="Exit 1 if any rule is expiring within --days"
    )
    suppress_expiring.set_defaults(func=cmd_suppress_expiring)

    return p


def _apply_rc(parser: argparse.ArgumentParser, rc: dict) -> None:
    updates: dict = {}
    if rc.get("mode"):
        updates["mode"] = rc["mode"]
    if "depth" in rc:
        updates["depth"] = int(rc["depth"])
    if "max_pages" in rc:
        updates["max_pages"] = int(rc["max_pages"])
    if "max_time" in rc:
        updates["max_time"] = float(rc["max_time"])
    if rc.get("ignore_robots"):
        updates["ignore_robots"] = True
    if rc.get("allow_external"):
        updates["allow_external"] = True
    if rc.get("format"):
        updates["format"] = rc["format"]
    if rc.get("cookie_jar"):
        updates["cookie_jar"] = rc["cookie_jar"]
    if rc.get("storage_state"):
        updates["storage_state"] = rc["storage_state"]
    if rc.get("login_recipe"):
        updates["login_recipe"] = rc["login_recipe"]
    if not updates:
        return
    parser.set_defaults(**updates)
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for sub in action.choices.values():
                sub.set_defaults(**updates)


def _profile_from_argv(argv: list[str]) -> str | None:
    for i, a in enumerate(argv):
        if a == "--profile" and i + 1 < len(argv):
            return argv[i + 1]
        if a.startswith("--profile="):
            return a.split("=", 1)[1]
    return None


def _apply_profile(parser: argparse.ArgumentParser, name: str) -> None:
    preset = PROFILES.get(name)
    if not preset:
        return
    parser.set_defaults(**preset)
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for sub in action.choices.values():
                sub.set_defaults(**preset)


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    # Apply ~/.shroodlerrc defaults first, then an explicit --profile on top
    # of it, so a profile picked on the command line always wins over the
    # rc file's defaults for the same setting. An explicit flag on the
    # command line still wins over both, since parser.set_defaults() never
    # overrides a value the user actually typed.
    rc = load_rc()
    _apply_rc(parser, rc)
    profile_name = _profile_from_argv(list(argv if argv is not None else sys.argv[1:]))
    if profile_name:
        _apply_profile(parser, profile_name)
    args = parser.parse_args(argv)
    if getattr(args, "version", False) and not getattr(args, "command", None):
        raise SystemExit(cmd_version())
    if not getattr(args, "command", None):
        parser.print_help(sys.stderr)
        raise SystemExit(2)
    if getattr(args, "command", None) == "crawl":
        args.cookie = _as_str_list(rc.get("cookie")) + list(getattr(args, "cookie", None) or [])
        args.header = _as_str_list(rc.get("header")) + list(getattr(args, "header", None) or [])
    try:
        code = args.func(args)
    except Exception as exc:
        if getattr(args, "debug", False):
            raise
        print(f"error: {exc}", file=sys.stderr)
        print("(re-run with --debug for a full traceback)", file=sys.stderr)
        raise SystemExit(1) from exc
    raise SystemExit(code)


if __name__ == "__main__":
    main()
