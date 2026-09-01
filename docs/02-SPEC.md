# Spec: Data Contracts

## 1. Finding schema (`schema/finding.schema.json`)

Every crawl produces a single JSON document with this top-level shape:

```jsonc
{
  "target": "http://app1.local:8081",
  "scan_started_at": "2026-09-01T12:00:00Z",
  "scan_finished_at": "2026-09-01T12:00:42Z",
  "crawler": { "name": "shroodler-py", "version": "0.1.0", "mode": "static" },
  "pages": [
    {
      "url": "http://app1.local:8081/login",
      "status_code": 200,
      "forms": [
        {
          "action": "/login",
          "method": "POST",
          "fields": [
            { "name": "username", "type": "text", "hidden": false },
            { "name": "password", "type": "password", "hidden": false },
            { "name": "csrf_token", "type": "hidden", "hidden": true }
          ]
        }
      ],
      "params": ["redirect_to"],
      "cookies": [
        { "name": "session_id", "secure": false, "http_only": true, "same_site": "Lax" }
      ],
      "headers": {
        "present": ["X-Frame-Options"],
        "missing": ["Content-Security-Policy", "Strict-Transport-Security"]
      },
      "js_files": ["/static/app.js"]
    }
  ],
  "findings": [
    {
      "id": "missing-csp",
      "severity": "medium",
      "category": "header",
      "url": "http://app1.local:8081/login",
      "description": "Content-Security-Policy header not set",
      "evidence": null
    },
    {
      "id": "leaked-secret",
      "severity": "high",
      "category": "secret",
      "url": "http://app1.local:8081/static/app.js",
      "description": "AWS access key pattern matched",
      "evidence": "AKIA************" 
    }
  ],
  "js_endpoints": [
    { "source": "/static/app.js", "endpoint": "/api/internal/debug" }
  ],
  "stats": {
    "pages_crawled": 12,
    "requests": 28,
    "elapsed_ms": 42000
  }
}
```

Rules:
- `severity` is one of `info | low | medium | high | critical`.
- `category` is one of `header | cookie | secret | exposed-file | js-endpoint | verbose-error | autocomplete`.
- `evidence` should be redacted/truncated for anything secret-like — never store a full
  raw key even in test fixtures, truncate to first/last few chars.
- Field order in the JSON doesn't matter; consumers must not rely on it. Parity tests
  compare structurally (parsed objects), not as raw text diffs.
- `stats` is optional. Older scans omit it and still validate. When present, engines may
  include `pages_crawled`, `requests` (HTTP fetches, when counted), and `elapsed_ms`.
  Parity tests ignore `stats` the same way they ignore timestamps — counts need not match
  across Python and Go.

## 2. `expected_findings.json` (per target app)

Each target app under `packages/target-apps/*/` ships an `expected_findings.json` that
lists exactly what a correct crawl should find. This is the ground truth used by
integration tests.

```jsonc
{
  "target_app": "app1-server-rendered",
  "expected_pages": ["/", "/login", "/dashboard", "/settings"],
  "expected_forms": {
    "/login": ["username", "password", "csrf_token"]
  },
  "expected_findings": [
    { "id": "missing-csp", "url": "/login" },
    { "id": "insecure-cookie", "url": "/dashboard", "cookie": "session_id" }
  ],
  "expected_not_found": [
    { "id": "leaked-secret", "url": "/about" }
  ]
}
```

The `expected_not_found` block matters as much as `expected_findings` — it's how you
catch false positives, not just false negatives.

Integration test logic: run crawler against the app, load actual output, assert every
`expected_findings` entry is present and every `expected_not_found` entry is absent.

## 3. CLI contract

```
shroodler crawl <url> [--mode static|headless] [--depth N] [--output out.json]
                 [--proxy http://127.0.0.1:8888]
                 [--header 'Name: value'] [--cookie 'name=value'] [--cookie-jar FILE]
                 [--storage-state FILE] [--login-recipe FILE]
                 [--seed url ...] [--seed-from sessions.jsonl]
                 [--cookies-from sessions.jsonl] [--ignore-robots] [--no-sitemap]
shroodler ingest-sessions <sessions.jsonl> [--target url] [--output out.json]
shroodler report <findings.json> [--format html|csv|json|sarif|junit] [--output out]
shroodler diff <findings.json> <expected_findings.json>
           [--pages-only] [--gate] [--suppressions FILE] [--format text|junit|sarif]
shroodler baseline <findings.json> [--output expected_findings.json] [--name NAME]
           [--suppressions FILE]
shroodler expected <findings.json> [--output expected_findings.json] [--name NAME]
           [--suppressions FILE]
shroodler payload <crawl.json> [--output out.json]
```

`shroodler payload` (Go CLI) and `packages/payload-tester/tester.py` (Python) both load
`payload-tester/packs/*.yaml` — see section 4b. Local targets only.

`shroodler diff` is what the test suite shells out to — keep it scriptable and exit-code
driven, no interactive prompts.

`--proxy` sends every crawler fetch through an HTTP proxy (the `shroodler-proxy`
listener). `--header` is repeatable `Name: value` and is sent on every crawler HTTP
request (static mode in both languages). `--cookie` is repeatable `name=value` loaded
into the crawl cookie jar so those cookies go out on every request; `--cookie-jar`
loads the same jar from a Netscape cookies.txt, JSON list, or Playwright storageState
file. `--storage-state` is an alias for a Playwright storageState JSON file.
`--login-recipe` is a JSON object `{ "url", "method", "fields" }` executed once before
the crawl (GET the URL, merge hidden inputs, POST the fields; cookies persist).
`--cookies-from` adds to that jar from `Set-Cookie` / request `Cookie` fields in
captured proxy sessions for the same origin. Extra headers and cookies do not change
same-origin scope or `--allow-external`. `--seed` / `--seed-from` enqueue extra
same-origin URLs (browsed paths the link crawler would miss). Repeat `--seed` as needed.
Crawls also seed from same-origin `robots.txt` `Sitemap:` directives and `/sitemap.xml`
`<loc>` entries (including a simple nested sitemap index). Off-host sitemap locs are
ignored. `--no-sitemap` disables that discovery.

`.shroodlerrc` (cwd, then `$HOME`) may set the same crawl defaults as flags, including
`header` (list of `Name: value` strings) and `cookie` (list of `name=value` strings).

`ingest-sessions` runs the same extractors as a crawl over captured session bodies — no
live fetches. `crawler.mode` is `"ingest"`. Request bodies and headers are scanned for
secrets (proxy-only signal: POST bodies the GET crawler never sees). Incomplete sessions
(`response: null`) are skipped. Common-path probing is not run — ingest is passive.

Default `diff` is **fixture mode**: every `expected_findings` entry must be present
(crawler regression against the lab apps). `--gate` is **app baseline mode**: extra
findings not listed in the baseline (and not suppressed) fail the command; findings that
disappeared since the baseline are printed as `resolved` and do not fail. That is the
CI contract for any local app whose `expected_findings.json` lives in git.

`--suppressions` is a YAML file (see section 8). If the flag is omitted, both CLIs load
`.shroodlerignore` from the current working directory when that file exists.

`shroodler baseline` and `shroodler expected` are the same command (either name). They
write the `expected_findings.json` shape from a crawl document so a new local app can
check in a snapshot. Mapping: `pages[].url` → `expected_pages` (origin-stripped paths);
form field names → `expected_forms`; findings → `expected_findings` (`id` + path). Pages,
form field names, and finding pairs are sorted for stable git diffs. Suppressed findings
are omitted from `expected_findings`. `expected_not_found` is always `[]` — the generator
does not invent negatives; add those by hand so false-positive checks stay deliberate.

## 4. Secret pattern rule-pack format (`packages/secret-patterns/rules/*.yaml`)

```yaml
- id: aws-access-key
  pattern: 'AKIA[0-9A-Z]{16}'
  severity: high
  description: AWS Access Key ID
- id: generic-jwt
  pattern: 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
  severity: medium
  description: JWT-looking token
```

Both crawlers load every `rules/*.yaml` file at runtime — never hardcode patterns
directly in crawler source. Cloud/SaaS keys live in `rules/cloud.yaml`; core patterns
stay in `rules/secrets.yaml`.

Common-path probes are the same idea: both crawlers load every `wordlists/*.txt` file
(comments and blanks skipped, duplicates dropped). A new path is a wordlist line plus an
`expected_findings` / `expected_not_found` row on the fixture that should or shouldn't
serve it. Probed response bodies are scanned with the secret rule-pack, so a token in
`/.env` is a secret finding as well as `exposed-file`.

## 4b. Payload pack format (`packages/payload-tester/packs/*.yaml`)

```yaml
- id: payload-sql-error
  payload: "'"
  severity: high
  description: Payload triggered a database-looking error
  match:
    any:
      - status_gte: 500
      - body_contains: sql
      - body_contains: syntax error
- id: payload-xss-reflect
  payload: "<script>alert(1)</script>"
  severity: medium
  description: Payload reflected in response
  match:
    any:
      - reflected: true
```

`match.any` fires if any clause is true; `match.all` requires every clause. Clause keys:
`status_gte`, `body_contains` (case-insensitive), `reflected` (raw payload appears in the
response body). `finding_id` is optional and defaults to `id`. The Python tester and Go
`shroodler payload <crawl.json>` both load every `packs/*.yaml` file; `--pack PATH` merges
extra YAML. Local targets only. Ground truth is
`packages/target-apps/app5-injectable/expected_findings.json`.


## 5. Cross-language parity contract

`parity-tests/run_parity.py` runs both crawlers against the same target with the same
flags, then asserts:
- Same set of `pages[].url`
- Same set of `findings[].id + url` pairs (severity/description text may differ slightly
  in wording, but category + id + location must match)
- Both outputs validate against `finding.schema.json`

Minor formatting differences (timestamps, crawler.version, `stats`) are ignored in the
diff. Request counts and elapsed time are not required to match across engines.

## 6. Desktop app contract

The desktop app (`packages/desktop-app/`) is a thin orchestration/rendering layer over
`shroodler-go`. It introduces no new finding schema — every scan it runs produces the
same `finding.schema.json`-valid JSON as the CLI.

**Local storage**: completed scans are saved as-is (unmodified schema JSON) under the OS
app-data directory, e.g. `~/Library/Application Support/Shroodler/scans/<id>.json` on
macOS, one file per scan, filename/id including a timestamp and target slug.

**Tauri commands** (frontend → Rust shell):
```
start_scan(target, mode, depth, via_proxy?, cookie?, cookie_jar?, login_recipe?, seeds?) -> scan_id
stop_scan(scan_id: string)
list_scans() -> [{ id, target, started_at, finished_at, finding_count }]
load_scan(scan_id: string) -> full finding.schema.json document
diff_scans(base_id: string, compare_id: string) -> { added: Finding[], resolved: Finding[] }
ingest_sessions(sessions, target) -> scan_id
```

**Tauri events** (Rust shell → frontend):
```
scan:progress   { scan_id, pages_crawled, current_url }
scan:complete   { scan_id, output_path }
scan:error      { scan_id, message }
```

`start_scan` invokes a crawler sidecar exactly as documented in section 3
(`shroodler crawl <target> --mode <mode> --depth <depth> --output <path>`), optionally
with `--proxy`, `--cookie`, `--cookie-jar`, `--login-recipe`, and `--seed`. Static mode
uses `shroodler-go`. Headless mode prefers the Python crawler (`SHROODLER_PY_BIN` or the
repo `.venv`) so Playwright Chromium is available; if that binary is missing it falls
through to `shroodler-go --mode headless` (chromedp, system Chrome). It streams
stdout for progress where the CLI emits it, and on exit reads back the output file rather
than re-implementing any parsing itself.

`ingest_sessions(sessions, target)` writes captured sessions as JSONL and runs
`shroodler ingest-sessions` on the Go sidecar — the desktop app does not re-derive
findings from bodies.

`diff_scans` matches findings by the same `id + url` equality rule defined in the parity
contract above (section 5) — this is app-side comparison logic only, not a new CLI flag,
and it is not held to the same ground-truth-testing bar as `expected_findings.json`
(there's no "expected diff," just a correctness property: every finding present in
`compare` but not `base` is `added`, every finding in `base` but not `compare` is
`resolved`).

The desktop app also manages `shroodler-proxy` as a second sidecar (start/stop it, open a
WebSocket connection to its control channel) — see `docs/07-PROXY-SPEC.md` for that
contract in full. The two sidecars are independent processes; the app coordinates both
but neither sidecar talks to the other. Fusion is a data-plane: crawl through the proxy
URL, ingest session JSONL into finding JSON, grow crawl seeds from captured URLs, and
hand cookies from a proxied login into `--cookie`.

**Site map**: the Map view is a rendering of `pages[]` (plus optional proxy session URLs)
from an already-loaded schema document. It does not crawl. Selecting a node shows that
page's forms, params, cookies, headers, and the findings whose `url` path matches.

**Baseline / CI exports from the GUI**: Save baseline, SARIF, JUnit, and `.shroodlerignore`
are format conversions of the loaded document (same rules as the CLI). They do not invent
findings.

## 7. Baseline file (`expected_findings.json`)

The per-target-app ground-truth file is also the productized baseline for any local app
under test. Shape is unchanged from section 2. `shroodler expected` (alias `baseline`)
emits:

```jsonc
{
  "target_app": "my-app",          // --name, else the crawl `target`
  "target": "http://127.0.0.1:3000",
  "expected_pages": ["/", "/login"],
  "expected_forms": { "/login": ["username", "password"] },
  "expected_findings": [{ "id": "missing-csp", "url": "/login" }],
  "expected_not_found": []
}
```

`url` values in `expected_findings` / `expected_not_found` are paths (`/login`), matching
the existing equality rule (`id` + path). Commit this file next to the app; CI crawls
localhost and runs `shroodler diff scan.json expected_findings.json --gate`.

## 8. Suppressions (`.shroodlerignore`)

YAML. Each rule matches a finding by `id` (exact, or `*` for any) and `url` (glob against
the finding path or full URL; `*` matches any string including slashes).

```yaml
suppressions:
  - id: missing-csp
    url: /static/*
    reason: "static file server has no CSP by design"
  - id: server-version-leak
    url: "*"
    reason: "dev server always sends Server"
```

A suppressed finding is excluded from `--gate` extra-finding failures, from
`shroodler baseline` output, and from SARIF/JUnit report results. It is not hidden from
the raw crawl JSON. `reason` is required in spirit (document why) but the parsers accept
a missing reason.

## 9. SARIF and JUnit

`shroodler report --format sarif` emits SARIF 2.1.0. Each finding is a `result` whose
`ruleId` is the finding `id`. Severity mapping: `critical`/`high` → `error`, `medium` →
`warning`, `low`/`info` → `note`. Location URI is the finding URL.

`shroodler report --format junit` emits a JUnit XML `testsuite`. Each finding is a
failing `testcase` (`classname` = category, `name` = `id` + URL) so CI surfaces them as
failed checks. `shroodler diff --format junit|sarif` encodes only mismatch rows (missing,
unexpected / gate extras) as failures; a clean diff is an empty-failure suite / empty
results run.
