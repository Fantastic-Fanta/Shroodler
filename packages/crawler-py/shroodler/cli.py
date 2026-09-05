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


def cmd_crawl(args: argparse.Namespace) -> int:
    depth = None if args.depth < 0 else args.depth
    max_pages = getattr(args, "max_pages", 400)
    max_time = getattr(args, "max_time", 0) or None
    cookies = list(getattr(args, "cookie", None) or [])
    headers = list(getattr(args, "header", None) or [])
    extra_seeds = list(getattr(args, "seed", None) or [])
    cookies_from = getattr(args, "cookies_from", None)
    seed_from = getattr(args, "seed_from", None)
    if cookies_from or seed_from:
        from shroodler.sessions import cookie_header, load_sessions, seed_urls

        if cookies_from:
            hdr = cookie_header(load_sessions(cookies_from), args.url)
            cookies.extend(p.strip() for p in hdr.split(";") if p.strip())
        if seed_from:
            extra_seeds.extend(seed_urls(load_sessions(seed_from), args.url))
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


def cmd_diff(args: argparse.Namespace) -> int:
    actual = load_json(args.findings)
    expected = load_json(args.expected)
    rules = load_suppressions(getattr(args, "suppressions", None))
    outcome = diff_outcome(
        actual,
        expected,
        pages_only=args.pages_only,
        gate=bool(getattr(args, "gate", False)),
        suppressions=rules,
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
    for line in outcome.resolved:
        print(line)
    if outcome.errors:
        for err in outcome.errors:
            print(err, file=sys.stderr)
        return 1
    print("diff ok")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    from shroodler.report import write_report

    doc = load_json(args.findings)
    rules = load_suppressions(getattr(args, "suppressions", None))
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


def cmd_authz_diff(args: argparse.Namespace) -> int:
    from shroodler.auth import parse_cookie_pairs, parse_header_lines
    from shroodler.authz_diff import run as authz_diff_run

    higher_doc = load_json(args.higher_crawl_json)
    cookie_pairs = parse_cookie_pairs(list(getattr(args, "cookie", None) or []))
    cookie_header = "; ".join(f"{c.name}={c.value}" for c in cookie_pairs)
    extra_headers = parse_header_lines(list(getattr(args, "header", None) or []))
    out = authz_diff_run(
        higher_doc,
        cookie_header=cookie_header,
        extra_headers=extra_headers,
        check_anonymous=not bool(getattr(args, "no_anon_check", False)),
        allow_external=bool(getattr(args, "allow_external", False)),
    )
    text = json.dumps(out, indent=2) + "\n"
    _write(text, args.output)
    return 0


def cmd_baseline(args: argparse.Namespace) -> int:
    doc = load_json(args.findings)
    rules = load_suppressions(args.suppressions)
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
    trend = trend_diff(older, newer)
    if getattr(args, "format", "text") == "json":
        text = json.dumps(trend, indent=2) + "\n"
    else:
        text = render_trend_text(trend)
    _write(text, args.output)
    return 0


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


def cmd_payload(args: argparse.Namespace) -> int:
    tester_dir = _payload_tester_dir()
    if str(tester_dir) not in sys.path:
        sys.path.insert(0, str(tester_dir))
    import tester

    extra = [Path(x) for x in (getattr(args, "pack", None) or [])]
    doc = load_json(args.crawl_json)
    packs = tester.load_packs(extra=extra) if extra else tester.load_packs()
    out = tester.run(
        doc,
        packs=packs,
        allow_external=getattr(args, "allow_external", False),
        oob_host=getattr(args, "oob_host", None),
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
        help="JSON {url, method, fields} posted once before crawling (merges hidden fields)",
    )
    crawl.add_argument("--proxy", help="HTTP proxy URL, e.g. http://127.0.0.1:8888")
    crawl.add_argument(
        "--seed",
        action="append",
        default=[],
        help="Extra same-origin URL to enqueue (repeatable)",
    )
    crawl.add_argument("--seed-from", help="Proxy session JSONL; enqueue captured same-origin URLs")
    crawl.add_argument(
        "--cookies-from",
        help="Proxy session JSONL; Cookie header from captured Set-Cookie / Cookie",
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
    diff.add_argument("--suppressions", default=None)
    diff.add_argument("--format", choices=["text", "junit", "sarif"], default="text")
    diff.add_argument("--output", "-o")
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

    ingest = sub.add_parser("ingest-sessions", help="Turn captured proxy JSONL into findings")
    ingest.add_argument("sessions")
    ingest.add_argument("--target", default=None)
    ingest.add_argument("--output", "-o")
    ingest.add_argument(
        "--allow-external",
        action="store_true",
        help="Allow ingesting sessions captured against a non-local target; off by default",
    )
    ingest.set_defaults(func=cmd_ingest)

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
    payload.set_defaults(func=cmd_payload)

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
    authz.set_defaults(func=cmd_authz_diff)

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
    trend.set_defaults(func=cmd_trend)

    version = sub.add_parser("version", help="Print version")
    version.set_defaults(func=cmd_version)

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
