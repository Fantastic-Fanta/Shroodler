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
  ]
}
```

Rules:
- `severity` is one of `info | low | medium | high | critical`.
- `category` is one of `header | cookie | secret | exposed-file | js-endpoint | verbose-error | autocomplete`.
- `evidence` should be redacted/truncated for anything secret-like — never store a full
  raw key even in test fixtures, truncate to first/last few chars.
- Field order in the JSON doesn't matter; consumers must not rely on it. Parity tests
  compare structurally (parsed objects), not as raw text diffs.

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
shroodler report <findings.json> [--format html|csv] [--output out.html]
shroodler diff <findings.json> <expected_findings.json>   # exits non-zero on mismatch
```

`shroodler diff` is what the test suite shells out to — keep it scriptable and exit-code
driven, no interactive prompts.

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

Both crawlers load this file at runtime (or compile it in at build time for Go) — never
hardcode patterns directly in crawler source.

## 5. Cross-language parity contract

`parity-tests/run_parity.py` runs both crawlers against the same target with the same
flags, then asserts:
- Same set of `pages[].url`
- Same set of `findings[].id + url` pairs (severity/description text may differ slightly
  in wording, but category + id + location must match)
- Both outputs validate against `finding.schema.json`

Minor formatting differences (timestamps, crawler.version) are ignored in the diff.

## 6. Desktop app contract

The desktop app (`packages/desktop-app/`) is a thin orchestration/rendering layer over
`shroodler-go`. It introduces no new finding schema — every scan it runs produces the
same `finding.schema.json`-valid JSON as the CLI.

**Local storage**: completed scans are saved as-is (unmodified schema JSON) under the OS
app-data directory, e.g. `~/Library/Application Support/Shroodler/scans/<id>.json` on
macOS, one file per scan, filename/id including a timestamp and target slug.

**Tauri commands** (frontend → Rust shell):
```
start_scan(target: string, mode: "static" | "headless", depth: number) -> scan_id
stop_scan(scan_id: string)
list_scans() -> [{ id, target, started_at, finished_at, finding_count }]
load_scan(scan_id: string) -> full finding.schema.json document
diff_scans(base_id: string, compare_id: string) -> { added: Finding[], resolved: Finding[] }
```

**Tauri events** (Rust shell → frontend):
```
scan:progress   { scan_id, pages_crawled, current_url }
scan:complete   { scan_id, output_path }
scan:error      { scan_id, message }
```

`start_scan` invokes the `shroodler-go` sidecar exactly as documented in section 3
(`shroodler crawl <target> --mode <mode> --depth <depth> --output <path>`), streams its
stdout for progress where the CLI emits it, and on exit reads back the output file rather
than re-implementing any parsing itself.

`diff_scans` matches findings by the same `id + url` equality rule defined in the parity
contract above (section 5) — this is app-side comparison logic only, not a new CLI flag,
and it is not held to the same ground-truth-testing bar as `expected_findings.json`
(there's no "expected diff," just a correctness property: every finding present in
`compare` but not `base` is `added`, every finding in `base` but not `compare` is
`resolved`).

The desktop app also manages `shroodler-proxy` as a second sidecar (start/stop it, open a
WebSocket connection to its control channel) — see `docs/07-PROXY-SPEC.md` for that
contract in full. The two sidecars are independent processes; the app coordinates both
but neither sidecar talks to the other.
