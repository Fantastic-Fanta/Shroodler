from __future__ import annotations

import argparse
import sys
from pathlib import Path

from shroodler.commands import (
    _as_str_list,
    cmd_agent,
    cmd_ask,
    cmd_attack_path,
    cmd_audit_verify,
    cmd_authz_diff,
    cmd_baseline,
    cmd_cadence,
    cmd_ci_template,
    cmd_compare_engines,
    cmd_crawl,
    cmd_dedup,
    cmd_diff,
    cmd_discover,
    cmd_engagement_diff,
    cmd_engagement_history,
    cmd_eval,
    cmd_gen_regression_test,
    cmd_history_list,
    cmd_history_record,
    cmd_ingest,
    cmd_js_routes,
    cmd_mcp_server,
    cmd_nuclei_ingest,
    cmd_paced_fetch,
    cmd_payload,
    cmd_peer_write,
    cmd_program_add_session,
    cmd_program_init,
    cmd_program_merge,
    cmd_program_scope,
    cmd_program_status,
    cmd_proxy,
    cmd_report,
    cmd_reverify,
    cmd_self_scan,
    cmd_session_export,
    cmd_sla_apply,
    cmd_slither_ingest,
    cmd_suppress,
    cmd_suppress_expiring,
    cmd_ticket_file,
    cmd_ticket_sync,
    cmd_tokens,
    cmd_trend,
    cmd_triage,
    cmd_triage_findings,
    cmd_version,
)
from shroodler.config import load_rc
from shroodler.robots import DEFAULT_UA

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
        "robots": "respect",
    },
    "balanced": {
        "depth": 5,
        "max_pages": 400,
        "max_time": 0.0,
        "check_rate_limit": False,
        "robots": "ignore",
    },
    "aggressive": {
        "depth": -1,
        "max_pages": 2000,
        "max_time": 0.0,
        "check_rate_limit": True,
        "robots": "harvest",
    },
}


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
        "--robots",
        choices=("respect", "ignore", "harvest"),
        default=None,
        help=(
            "robots.txt handling: respect (honor Disallow), ignore (crawl "
            "through it), or harvest (also seed and surface Disallow paths as "
            "recon leads). Defaults per --profile: safe=respect, "
            "balanced=ignore, aggressive=harvest."
        ),
    )
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
        help="JSON login recipe posted before crawling (merges hidden fields). "
        "If a later fetch returns 401 or a login redirect, the recipe is "
        "re-run up to --reauth-max-retries times with exponential backoff "
        "(1s, 2s, 4s). A recipe may include steps: oauth_pkce (token_url, "
        "client_id, scope — client-credentials or authorization-code+PKCE, "
        "injects Authorization: Bearer) and hook (an optional shell command "
        "run before the recipe, e.g. to fetch a Castle.io token). WARNING: "
        "a hook step executes arbitrary commands from the recipe file and "
        "must only be used with recipes you trust.",
    )
    crawl.add_argument(
        "--reauth-max-retries",
        type=int,
        default=3,
        metavar="N",
        help="How many times to re-run --login-recipe after a mid-crawl 401 "
        "or login redirect (default 3). Backoff is 1s, 2s, 4s. If every "
        "retry fails, emit a session-died finding and stop crawling that "
        "origin instead of continuing with a dead session.",
    )
    crawl.add_argument(
        "--program",
        metavar="SLUG",
        help="Merge this crawl into ~/.shroodler/programs/<SLUG>/state.json "
        "when the crawl finishes (creates the program if missing).",
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
    crawl.add_argument(
        "--seed-from",
        help="HAR or proxy session JSONL; enqueue captured same-origin URLs",
    )
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

    ev = sub.add_parser(
        "eval",
        help="Score a scan/agent result against expected findings (precision/recall)",
    )
    ev.add_argument("actual", help="Scan or agent result JSON (or a bare findings list)")
    ev.add_argument("expected", help="Expected-findings JSON (the curated ground truth)")
    ev.add_argument(
        "--baseline",
        default=None,
        metavar="JSON",
        help="A second run to A/B against `actual` (e.g. LLM tools off vs on); prints the delta",
    )
    ev.add_argument("--label", default="", help="Label for the scorecard")
    ev.add_argument("--json", action="store_true", help="Emit the scorecard as JSON")
    ev.set_defaults(func=cmd_eval)

    report = sub.add_parser(
        "report",
        help="Render findings JSON as HTML, CSV, SARIF, JUnit, Markdown, pentest, or submit",
    )
    report.add_argument("findings")
    report.add_argument(
        "--format",
        choices=[
            "html",
            "csv",
            "json",
            "sarif",
            "junit",
            "md",
            "markdown",
            "pentest",
            "pentest-html",
            "submit",
        ],
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
    report.add_argument(
        "--dedup",
        dest="dedup",
        action="store_true",
        default=True,
        help="Deduplicate findings before rendering (default on)",
    )
    report.add_argument(
        "--no-dedup",
        dest="dedup",
        action="store_false",
        help="Keep duplicate findings when rendering",
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

    triage_findings = sub.add_parser(
        "triage-findings",
        help="Score and rank crawl findings for bug-bounty submission",
        description=(
            "Load a crawl JSON document or program state.json, score each "
            "finding by exploitability and confidence, deduplicate repeats, "
            "and print which ones are worth submitting. Distinct from `triage`, "
            "which classifies hosts before a crawl."
        ),
    )
    triage_findings.add_argument(
        "state_file",
        help="Crawl JSON or program state.json (must contain a findings list)",
    )
    triage_findings.add_argument(
        "--min-score",
        type=int,
        default=50,
        help="Minimum exploitability (0-100) to mark worth_submitting (default 50)",
    )
    triage_findings.add_argument(
        "--min-confidence",
        type=int,
        default=65,
        help="Minimum confidence (0-100) to mark worth_submitting (default 65)",
    )
    triage_findings.add_argument(
        "--format",
        choices=["text", "json", "submit"],
        default="text",
        help="text table (default), json, or submission-ready Markdown",
    )
    triage_findings.add_argument("--output", "-o")
    triage_findings.set_defaults(func=cmd_triage_findings)

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
    authz.add_argument(
        "--program",
        metavar="SLUG",
        help="Mark replayed URLs as tested_authz in ~/.shroodler/programs/<SLUG>",
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
    peer.add_argument(
        "--program",
        metavar="SLUG",
        help="Mark replayed write URLs as tested_peer_write in "
        "~/.shroodler/programs/<SLUG>",
    )
    peer.add_argument(
        "--from-program",
        metavar="SLUG",
        help="Pull stored object IDs from ~/.shroodler/programs/<SLUG> and "
        "expand playbook writes across matching URL patterns",
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

    engagement_history = sub.add_parser(
        "engagement-history",
        help="Show per-program agent run history (date, iterations, confirmed, new endpoints)",
    )
    engagement_history.add_argument("--program", required=True, metavar="SLUG")
    engagement_history.set_defaults(func=cmd_engagement_history)

    engagement_diff = sub.add_parser(
        "engagement-diff",
        help="Show endpoint additions/removals/param changes since the previous agent run",
    )
    engagement_diff.add_argument("--program", required=True, metavar="SLUG")
    engagement_diff.set_defaults(func=cmd_engagement_diff)

    program = sub.add_parser(
        "program",
        help="Per-program engagement memory (endpoints, object IDs, coverage)",
        description=(
            "Persistent state under ~/.shroodler/programs/<slug>/state.json. "
            "Init a program, merge crawl JSON, track sessions, and list "
            "coverage gaps (endpoints not yet authz-diffed or peer-write tested)."
        ),
    )
    program_sub = program.add_subparsers(dest="program_command", required=True)
    pinit = program_sub.add_parser("init", help="Create program state (no-op if it exists)")
    pinit.add_argument("slug", help="Short identifier, e.g. etoro-bugcrowd")
    pinit.add_argument(
        "--scope-file",
        metavar="FILE",
        help="One URL/glob per line (lines starting with ! or - are out of scope)",
    )
    pinit.set_defaults(func=cmd_program_init)
    pstatus = program_sub.add_parser(
        "status", help="Print endpoint/finding counts, coverage gaps, stale sessions"
    )
    pstatus.add_argument("slug")
    pstatus.set_defaults(func=cmd_program_status)
    pmerge = program_sub.add_parser(
        "merge", help="Ingest a crawl JSON into program state and print the delta"
    )
    pmerge.add_argument("slug")
    pmerge.add_argument("crawl_json", help="Path to crawl JSON")
    pmerge.set_defaults(func=cmd_program_merge)
    padd = program_sub.add_parser(
        "add-session", help="Record a session jar/storageState path on the program"
    )
    padd.add_argument("slug")
    padd.add_argument("path", help="Path to a cookie jar, storageState, or HAR")
    padd.add_argument("--label", required=True, help="Session label, e.g. owner / peer")
    padd.add_argument(
        "--expires",
        metavar="ISO",
        help="Optional expiry hint (ISO-8601 date/datetime)",
    )
    padd.set_defaults(func=cmd_program_add_session)
    pscope = program_sub.add_parser(
        "scope", help="Write include/exclude host patterns to scope.json"
    )
    pscope.add_argument("--program", required=True, metavar="SLUG", help="Program slug")
    pscope.add_argument(
        "--include",
        action="append",
        default=[],
        metavar="PATTERN",
        help="Hostname glob to include (repeatable), e.g. *.example.com",
    )
    pscope.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="PATTERN",
        help="Hostname glob to exclude (repeatable); exclude wins",
    )
    pscope.set_defaults(func=cmd_program_scope)

    agent = sub.add_parser(
        "agent",
        help="Run the autonomous engagement loop for a program",
        description=(
            "Load ~/.shroodler/programs/<slug>/state.json, pick the next "
            "highest-value action (crawl coverage gaps, authz-diff, peer-write, "
            "or report confirmed findings), execute it, merge results, and loop "
            "until --max-iterations or there is nothing left to do. JSON lines "
            "go to stderr per iteration; a final {iterations, confirmed, "
            "state_path} summary goes to stdout. --dry-run prints the plan "
            "without making requests."
        ),
    )
    agent.add_argument("--program", required=True, metavar="SLUG", help="Program slug")
    agent.add_argument("--target", required=True, metavar="URL", help="Base URL to act on")
    agent.add_argument(
        "--max-iterations",
        type=int,
        default=10,
        metavar="N",
        help="Loop budget (default 10)",
    )
    agent.add_argument(
        "--max-pages-per-crawl",
        type=int,
        default=30,
        metavar="N",
        help="Cap on URLs queued for one crawl action (default 30)",
    )
    agent.add_argument(
        "--login-recipe",
        metavar="FILE",
        help="Login recipe JSON posted before TLS/crawl/probes; session cookies "
        "and extracted headers are reused on probe requests. On mid-probe "
        "401/403 the recipe is re-run up to --reauth-max-retries times.",
    )
    agent.add_argument(
        "--peer-recipe",
        metavar="FILE",
        help="Login recipe JSON for the peer/attacker account. After a "
        "successful owner login, this recipe is run separately and stored "
        "as peer_headers/peer_cookies (owner session is not overwritten).",
    )
    agent.add_argument(
        "--reauth-max-retries",
        type=int,
        default=3,
        metavar="N",
        help="How many times to re-run --login-recipe after a probe 401/403 "
        "(default 3). Set 0 to disable probe re-auth.",
    )
    agent.add_argument(
        "--higher-priv-jar",
        metavar="FILE",
        help="Higher-privilege cookie jar; enables the authz-diff leg",
    )
    agent.add_argument(
        "--lower-priv-jar",
        metavar="FILE",
        help="Lower-privilege cookie jar; enables the authz-diff leg",
    )
    agent.add_argument(
        "--owner-cookie",
        metavar="STR",
        help="Owner Cookie header; enables the peer-write leg",
    )
    agent.add_argument(
        "--peer-cookie",
        metavar="STR",
        help="Peer Cookie header; enables the peer-write leg",
    )
    agent.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the planned action each iteration; make no requests",
    )
    agent.add_argument(
        "--llm-triage",
        action="store_true",
        help=(
            "Rank unconfirmed leads with an LLM before acting "
            "(requires ANTHROPIC_API_KEY, or DEEPSEEK_API_KEY with --llm-provider deepseek)"
        ),
    )
    agent.add_argument(
        "--llm-agent",
        action="store_true",
        help=(
            "Use an LLM to decide each action "
            "(requires DEEPSEEK_API_KEY, or ANTHROPIC_API_KEY with --llm-provider anthropic)"
        ),
    )
    agent.add_argument(
        "--context",
        default=None,
        metavar="TEXT",
        help=(
            "Operator context about the target: what the app is, what matters, "
            "and what abuse means here (e.g. 'construction quoting app; quotes "
            "must be immutable after submit; coupons are single-use'). Grounds "
            "the LLM's business-logic hypotheses so it reasons about the real app "
            "instead of inventing endpoints."
        ),
    )
    agent.add_argument(
        "--prove-impact",
        action="store_true",
        help=(
            "After the scan, demonstrate bounded read-only impact for confirmed "
            "findings (e.g. read back the database version for a confirmed SQLi "
            "via a split-sentinel UNION, proving arbitrary SQL runs). Never "
            "dumps data or writes."
        ),
    )
    agent.add_argument(
        "--llm-provider",
        choices=["anthropic", "deepseek", "ollama"],
        default="deepseek",
        help=(
            "LLM provider (default: deepseek, the cheapest). deepseek uses "
            "DEEPSEEK_API_KEY; ollama runs a local daemon (no key, free, set "
            "--llm-agent-model to a pulled model like llama3.1 and OLLAMA_HOST "
            "if not on localhost:11434)"
        ),
    )
    agent.add_argument(
        "--llm-agent-model",
        dest="llm_agent_model",
        default="deepseek-chat",
        metavar="STR",
        help=(
            "Cheap high-volume planner model (default: deepseek-chat; for "
            "Anthropic, claude-sonnet-5 / 'opus'). Same field as --llm-model; "
            "last flag wins"
        ),
    )
    agent.add_argument(
        "--llm-model",
        dest="llm_agent_model",
        metavar="STR",
        help="Alias for --llm-agent-model (last of --llm-model / --llm-agent-model wins)",
    )
    agent.add_argument(
        "--llm-reasoning-model",
        dest="llm_agent_reasoning_model",
        default="deepseek-reasoner",
        metavar="STR",
        help=(
            "Stronger model for hard reasoning only (analyze_logic, "
            "verify_finding); default: deepseek-reasoner. Bulk work stays on "
            "the cheap planner model"
        ),
    )
    agent.add_argument(
        "--no-auto-verify",
        action="store_true",
        help=(
            "Skip the automatic evidence-based verification of tentative "
            "findings before the LLM agent reports (on by default)"
        ),
    )
    agent.add_argument(
        "--llm-verify",
        action="store_true",
        help=(
            "After the scan, run the LLM verifier over tentative findings to "
            "confirm, downgrade, or drop false positives (requires a provider "
            "key; uses --llm-provider / --llm-reasoning-model)"
        ),
    )
    agent.add_argument(
        "--llm-agent-max-cost",
        type=float,
        default=5.0,
        metavar="N",
        help="Stop if estimated API cost exceeds N USD (default: 5.0)",
    )
    agent.add_argument(
        "--run-discovery",
        action="store_true",
        help="Run subdomain/JS discovery before the first iteration",
    )
    agent.add_argument(
        "--ignore-robots",
        action="store_true",
        help="Bypass robots.txt during crawl legs (use for API-first targets)",
    )
    agent.add_argument(
        "--robots",
        choices=("respect", "ignore", "harvest"),
        default=None,
        help=(
            "robots.txt handling: respect (honor Disallow), ignore (crawl "
            "through it), or harvest (also seed and surface Disallow paths as "
            "recon leads). Maps to the scan profile: safe=respect, "
            "balanced=ignore, aggressive=harvest."
        ),
    )
    agent.add_argument(
        "--run-probes",
        action="store_true",
        help=(
            "Run active injection probes (SQLi/XSS/path-traversal/JWT/IDOR/"
            "SSRF/open-redirect/host-header/SSTI/XXE/GraphQL) after authz and "
            "peer-write legs"
        ),
    )
    agent.add_argument(
        "--no-time-sqli",
        action="store_true",
        help="Skip time-based SQLi (SLEEP/WAITFOR). Error-based and boolean still run.",
    )
    agent.add_argument(
        "--no-openapi",
        action="store_true",
        help="Disable OpenAPI spec discovery and spec-driven probes",
    )
    agent.add_argument(
        "--no-ssrf",
        action="store_true",
        help="Disable SSRF probes (on by default when --run-probes is set)",
    )
    agent.add_argument(
        "--no-open-redirect",
        action="store_true",
        help="Disable open-redirect probes (on by default when --run-probes is set)",
    )
    agent.add_argument(
        "--no-host-header",
        action="store_true",
        help="Disable host-header injection probes (on by default when --run-probes is set)",
    )
    agent.add_argument(
        "--no-ssti",
        action="store_true",
        help="Disable SSTI probes (on by default when --run-probes is set)",
    )
    agent.add_argument(
        "--no-xxe",
        action="store_true",
        help="Disable XXE probes (on by default when --run-probes is set)",
    )
    agent.add_argument(
        "--no-graphql",
        action="store_true",
        help="Disable GraphQL probes (on by default when --run-probes is set)",
    )
    agent.add_argument(
        "--dom-xss",
        action="store_true",
        help="Enable DOM XSS probes (Playwright; off by default)",
    )
    agent.add_argument(
        "--no-crlf",
        action="store_true",
        help="Disable CRLF header-injection probes (on by default when --run-probes is set)",
    )
    agent.add_argument(
        "--no-prototype-pollution",
        action="store_true",
        help="Disable prototype-pollution probes (on by default when --run-probes is set)",
    )
    agent.add_argument(
        "--no-content-discovery",
        action="store_true",
        help="Skip the one-shot content-discovery pass",
    )
    agent.add_argument(
        "--no-tls-check",
        action="store_true",
        help="Skip the one-shot TLS certificate check",
    )
    agent.add_argument(
        "--no-waf-detect",
        action="store_true",
        help="Skip WAF fingerprinting (on by default; evasion variants apply when a WAF is found)",
    )
    agent.add_argument(
        "--oob",
        action="store_true",
        help="Enable OOB collaborator (local HTTP callback listener)",
    )
    agent.add_argument(
        "--oob-listen",
        default="127.0.0.1:8765",
        metavar="HOST:PORT",
        help="Bind address (default 127.0.0.1:8765)",
    )
    agent.add_argument(
        "--oob-public-url",
        default="",
        metavar="URL",
        help=(
            "URL the target should fetch (ngrok/interactsh/etc). "
            "Default: http://listen"
        ),
    )
    agent.add_argument(
        "--no-rate-limit-check",
        action="store_true",
        help="Disable missing-rate-limit probes (on by default when --run-probes is set)",
    )
    agent.add_argument(
        "--no-mass-assignment",
        action="store_true",
        help="Disable mass-assignment probes (on by default when --run-probes is set)",
    )
    agent.add_argument(
        "--aggressive",
        action="store_true",
        help=(
            "Aggressive mode: no request pacing, probe endpoints concurrently, "
            "and enable smuggling probes. Faster but hammers the target; use only "
            "on hosts you are authorized to stress"
        ),
    )
    agent.add_argument(
        "--smuggling",
        action="store_true",
        help="Enable HTTP request-smuggling probes (off by default)",
    )
    agent.add_argument(
        "--no-smuggling",
        action="store_true",
        help="Force HTTP request-smuggling probes off",
    )
    agent.add_argument(
        "--no-websocket",
        action="store_true",
        help="Disable WebSocket discovery/probes (on by default when --run-probes is set)",
    )
    agent.add_argument(
        "--no-js-analysis",
        action="store_true",
        help="Skip deep JavaScript bundle analysis after crawl (on by default)",
    )
    agent.add_argument(
        "--allow-external",
        action="store_true",
        help="Allow smuggling probes against non-localhost targets",
    )
    agent.add_argument(
        "--scope-file",
        metavar="FILE",
        help="Load include/exclude host patterns from FILE instead of program scope.json",
    )
    agent.add_argument(
        "--no-auto-register",
        action="store_true",
        help="Do not auto-register a peer account before authz-diff",
    )
    agent.add_argument(
        "--reprobe",
        action="store_true",
        help="Reset tested_payload on all endpoints before the agent loop starts",
    )
    agent.add_argument(
        "--write-authz-spec",
        metavar="FILE",
        help=(
            "JSON file of write probes (POST/PATCH/DELETE) replayed as both "
            "principals after authz-diff"
        ),
    )
    agent.add_argument(
        "--run-diff",
        action="store_true",
        help=(
            "Diff endpoints against the previous engagement snapshot after crawl. "
            "Also auto-runs when run_history is non-empty."
        ),
    )
    agent.add_argument(
        "--llm-business-logic",
        action="store_true",
        help=(
            "Infer app domain with an LLM and run business-logic probes "
            "(requires ANTHROPIC_API_KEY, or DEEPSEEK_API_KEY with --llm-provider deepseek; "
            "skipped with an error if unset)"
        ),
    )
    agent.add_argument(
        "--chain-spec",
        action="append",
        metavar="FILE",
        help="Operator attack-chain JSON spec (repeatable). Runs regardless of --run-probes.",
    )
    agent.add_argument(
        "--workflow-mutate",
        action="store_true",
        help=(
            "For each --chain-spec workflow that completes, also run skip-step "
            "and replay-the-final-action bypass mutations and flag any that still "
            "succeed (workflow-step-skip / workflow-replay)."
        ),
    )
    agent.set_defaults(func=cmd_agent)

    dedup = sub.add_parser(
        "dedup",
        help="Deduplicate findings JSON by id/url/param and host-level checks",
    )
    dedup.add_argument("findings", help="Crawl JSON or a raw findings array")
    dedup.add_argument("--output", "-o", help="Write deduplicated JSON to FILE")
    dedup.set_defaults(func=cmd_dedup)

    ci_template = sub.add_parser(
        "ci-template",
        help="Print a ready-to-paste CI workflow for shroodler crawl+diff",
    )
    ci_template.add_argument(
        "--platform",
        required=True,
        choices=["github", "gitlab", "bitbucket"],
        help="CI platform",
    )
    ci_template.add_argument("--program", metavar="SLUG", help="Pre-fill --program")
    ci_template.add_argument("--target", metavar="URL", help="Pre-fill crawl target URL")
    ci_template.set_defaults(func=cmd_ci_template)

    discover = sub.add_parser(
        "discover",
        help="Find live subdomains and JS API endpoints for a program",
        description=(
            "Query crt.sh for the target's apex domain, probe candidate FQDNs, "
            "and expand JS API surface from the latest scan's pages. Merges new "
            "scope URLs and endpoints into program state so the agent loop can "
            "pick them up. --dry-run prints counts without writing state. JSON "
            "summary goes to stdout."
        ),
    )
    discover.add_argument("--program", required=True, metavar="SLUG", help="Program slug")
    discover.add_argument(
        "--target",
        required=True,
        metavar="URL",
        help="Base URL (apex derived from this)",
    )
    discover.add_argument(
        "--max-subdomains",
        type=int,
        default=300,
        metavar="N",
        help="Cap candidate FQDNs before probing (default 300)",
    )
    discover.add_argument(
        "--probe-workers",
        type=int,
        default=20,
        metavar="N",
        help="Concurrent live probes (default 20)",
    )
    discover.add_argument(
        "--skip-crtsh",
        action="store_true",
        help="Skip Certificate Transparency (crt.sh) discovery",
    )
    discover.add_argument(
        "--skip-js-surface",
        action="store_true",
        help="Skip JS API surface expansion",
    )
    discover.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be added; do not write program state",
    )
    discover.set_defaults(func=cmd_discover)

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
            "  program_state       compact engagement briefing for a program slug\n"
            "  coverage_gaps       untested endpoints from program memory\n"
            "  run_agent           autonomous crawl/authz-diff/peer-write loop\n"
            "  discover_scope      live subdomains (crt.sh) + JS API endpoints\n"
            "Active tools require a scan-policy consent manifest by default. "
            "Finding tools default to compact summary output (summary=false for full JSON). "
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
            "Correlates every finding with how many clicks it is from the start "
            "URL. When the crawl recorded edges, that distance is a walk of those "
            "links (an HTML link or form action is one click; a redirect is not). "
            "A crawl file with no edges still loads and is ranked by URL path "
            "depth instead; the report says that is a heuristic. Also notes "
            "when this same scan found a guessable session/reset token."
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
    suppress.add_argument("--program", metavar="SLUG", help="Program slug (engagement suppress)")
    suppress.add_argument(
        "--id",
        dest="finding_id",
        metavar="FINDING_ID",
        help="Finding id to suppress on a program",
    )
    suppress.add_argument("--url", help="Finding URL, or * to match every URL for this id")
    suppress.add_argument("--reason", help="Why this finding is accepted/suppressed")
    suppress.set_defaults(func=cmd_suppress)
    suppress_sub = suppress.add_subparsers(dest="suppress_command", required=False)
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
