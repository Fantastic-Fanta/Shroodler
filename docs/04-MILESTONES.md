# Milestones

Work through these in order. Each milestone's "Definition of Done" must be fully true
(including `make verify` passing) before moving to the next.

## Milestone 0 — Scaffold
- [x] Repo tree matches `01-ARCHITECTURE.md`
- [x] `docker-compose.yml` exists with placeholder services for all 4 target apps
- [x] `Makefile` has a `verify` target that runs (even as a no-op stub)
- [x] `schema/finding.schema.json` created matching `02-SPEC.md`
- **Done when:** `make verify` runs and exits 0 with no real checks yet.

## Milestone 1 — Target app 1 (server-rendered)
- [x] Flask (or Express) app with: home page, login form, dashboard (session-gated),
      settings page, an exposed `.git/config`, a `backup.sql.bak`, one page missing CSP,
      one insecure cookie, one page with a verbose stack-trace error
- [x] `expected_findings.json` written for it
- **Done when:** app runs via `docker compose up app1` and is manually reachable.

## Milestone 2 — Python crawler MVP
- [x] Static crawler: fetch, parse links, depth limit, same-origin scope, dedupe
- [x] Matrix rows under "Crawler core" implemented as tests, passing against app1
- **Done when:** `shroodler crawl http://app1.local:8081` produces valid schema JSON and
      `shroodler diff` against `expected_findings.json` passes for page discovery.

## Milestone 3 — Extractors (forms, headers, cookies)
- [ ] Implement all three extractors
- [ ] Full matrix rows for "Form extraction", "Header analysis", "Cookie analysis" green
- **Done when:** diff against app1's `expected_findings.json` passes on all these categories.

## Milestone 4 — Secret pattern rule-pack + scanner
- [ ] `secret-patterns` package with initial 8 patterns from the test matrix
- [ ] Scanner wired into crawler, scans response bodies + JS files
- [ ] Fuzz tests running (no crashes on random input)
- **Done when:** matrix rows under "Secret detection" green, fuzz suite runs for at
      least a few thousand iterations clean.

## Milestone 5 — Common-path prober
- [ ] Wordlist-based prober for exposed files
- [ ] Matrix rows green against app1 (positives) with zero false positives
- **Done when:** diff passes including exposed-file findings.

## Milestone 6 — Target app 2 (SPA) + headless mode
- [ ] React SPA target app where key content loads via `fetch()` after mount
- [ ] `expected_findings.json` for it
- [ ] Playwright-based headless crawl mode in `crawler-py`
- **Done when:** headless mode discovers pages/forms that static mode provably misses
      (write a test asserting static mode under-reports on this app, headless does not).

## Milestone 7 — Target app 3 (crawler traps) + robustness
- [ ] Infinite pagination, redirect loop, honeypot links, rate-limited endpoint
- [ ] Crawler correctly terminates/handles each without hanging or crashing
- **Done when:** crawl against app3 completes in bounded time and matches expected findings.

## Milestone 8 — Report generator
- [ ] JSON → HTML and JSON → CSV
- [ ] Snapshot tests per `03-TEST-MATRIX.md` report section
- **Done when:** `shroodler report` produces valid, human-readable output for all target apps.

## Milestone 9 — Go port
- [ ] Port crawler core, extractors (excluding headless), secret scanner, common-path
      prober to Go
- [ ] Go implementation consumes the same `schema/finding.schema.json` and
      `secret-patterns` YAML files
- **Done when:** Go crawler independently passes the same integration tests as Python
      (excluding headless-only cases) against app1 and app3.

## Milestone 10 — Target app 4 (microservices) + parity tests
- [ ] Gateway + 2-3 backend services, at least one cross-service auth flow
- [ ] `expected_findings.json` covering multi-host recon
- [ ] `parity-tests/run_parity.py` runs both crawlers against app1, app3, app4 and diffs
- **Done when:** parity test suite is green across all three shared target apps.

## Milestone 11 — CLI polish
- [ ] Config file support (`.shroodlerrc` or similar) for default flags
- [ ] Multiple output formats wired through consistently in both language CLIs
- **Done when:** CLI contract in `02-SPEC.md` fully implemented in both languages.

## Milestone 12 — Proxy engine core: CA + capture
- [ ] Read `docs/07-PROXY-SPEC.md` in full before starting — it's the source of truth for
      this whole feature, the same way `02-SPEC.md` is for the crawler
- [ ] Scaffold `packages/proxy-go/`, produce the `shroodler-proxy` binary
- [ ] `schema/proxy-session.schema.json` created matching section 1 of the proxy spec
- [ ] Root CA generation/export/uninstall (`shroodler-proxy ca ...`)
- [ ] Core HTTP(S) capture: proxy listener, on-the-fly leaf cert signing, session
      recording via `--record` to JSONL
- [ ] Matrix rows under "Proxy capture core" and "Root CA management" green
- **Done when:** `shroodler-proxy start --record out.jsonl`, pointing curl or a browser
  at it (HTTP and HTTPS, after trusting the exported CA) produces valid schema-conformant
  captured sessions.

## Milestone 13 — Proxy control channel + session inspector data
- [ ] WebSocket control channel per section 3 of the proxy spec (`session:new`,
      `session:complete`, `subscribe`)
- [ ] Body decoding for the inspector: JSON, form-urlencoded, multipart, gzip/br/deflate,
      binary fallback
- [ ] Matrix rows under "Session inspector / decoding" green
- **Done when:** a client connected to the control channel receives real-time session
  events with correctly decoded bodies for a live capture.

## Milestone 14 — Breakpoints + AutoResponder
- [ ] Breakpoint engine: request-stage and response-stage pausing, resume/edit/drop,
      concurrent breakpoints, timeout auto-drop
- [ ] AutoResponder: rule loading, first-match-wins evaluation, passthrough on no match
- [ ] Matrix rows under "Breakpoints" and "AutoResponder" green
- **Done when:** a breakpoint rule reliably pauses matching traffic for edit/drop, and an
  AutoResponder rule reliably mocks a response without contacting the real upstream.

## Milestone 15 — Replay & composer
- [ ] Replay a captured session (unmodified and with edits) through the proxy pipeline,
      tagged `replayed_from`
- [ ] Composer path: build and send a request with no originating session
- [ ] Matrix rows under "Replay & composer" green
- **Done when:** both replay and from-scratch composition work via the CLI (`shroodler-
  proxy replay ...`) without the GUI, per the proxy spec's CLI contract.

## Milestone 16 — Desktop app shell + scan trigger
- [ ] Read `docs/06-UI-STYLE.md` in full before writing any UI code — it is the single
      source of truth for colors, typography, layout, and motion in this app, the same
      way `02-SPEC.md` is for the JSON schema
- [ ] Scaffold `packages/desktop-app/` — Tauri v2 (pin this version explicitly in
      `Cargo.toml`/`package.json`, do not mix v1 patterns) with a Svelte frontend
- [ ] Rust shell invokes the `shroodler-go` binary as a sidecar process — the desktop app
      contains zero scanning/extraction logic of its own, it only orchestrates and renders
- [ ] Basic window: target input, start/stop scan, live progress (page count, current URL)
      via a Tauri event stream from the Rust shell
- [ ] Dark theme applied per the style doc's color tokens (no default Tauri/OS light theme)
- **Done when:** entering a local target URL and clicking "scan" runs a real crawl via the
  Go sidecar and shows a completion state with the output file location.

## Milestone 17 — Results dashboard
- [ ] Findings table: sortable/filterable by severity/category, detail drawer on row select
- [ ] Scan history sidebar — past scans persisted locally (e.g. under the OS app-data dir),
      selectable to reload their results
- [ ] Motion for filtering, drawer open/close, and new-finding entry per the rules in
      `docs/06-UI-STYLE.md`
- **Done when:** a completed scan's full findings are browsable and filterable natively in
  the app, matching the data already produced by the CLI/report generator.

## Milestone 18 — Baseline/diff view
- [ ] Pick any two saved scans from history and view a diff: findings added vs resolved
      since the baseline, matched by the same `id + url` equality rule used in the
      cross-language parity contract (`02-SPEC.md` section 5) — this is computed by the
      desktop app itself, not a new CLI flag
- [ ] Diff view gets the slightly more noticeable "this changed" motion treatment called
      out as the one exception in the style doc's motion section
- **Done when:** comparing two scans of the same target clearly shows what's new and
  what's resolved, without needing to read raw JSON.

## Milestone 19 — Desktop app: proxy session list + inspector
- [ ] Manage `shroodler-proxy` as a second sidecar (start/stop, connect to its control
      channel per `docs/07-PROXY-SPEC.md`)
- [ ] Live session list view, updating in real time as traffic is captured
- [ ] Request/response inspector: headers, decoded body, cookies, per section 1/8 of the
      proxy spec, including the opt-in secret-pattern scan action
- [ ] CA install/export/uninstall exposed in-app, with an explicit confirmation step
      before installing a root CA (never silent)
- **Done when:** traffic routed through the proxy from a local target app is visible and
  inspectable live in the app, and CA install/uninstall both work from the UI.

## Milestone 20 — Desktop app: composer, breakpoints, AutoResponder UI
- [ ] Composer view: build and send a request from scratch or from an edited existing
      session
- [ ] Breakpoint UI: define rules, get notified on `breakpoint:hit`, edit/resume/drop
- [ ] AutoResponder rule editor, backed by the same YAML rule format from the proxy spec
- **Done when:** all three (composer, breakpoints, AutoResponder) are usable end-to-end
  from the GUI without hand-editing YAML or using the proxy's CLI.

## Milestone 21 — Coverage-gate loop
- [ ] Run coverage tooling on all implementations
- [ ] Iterate: find uncovered branch → add matrix row → add test → repeat
- **Done when:** ≥90% coverage on `crawler-py`, `crawler-go`, and `proxy-go`.

## Milestone 22 — Docs
- [ ] Auto-generated API/module docs (docstrings → docs site or markdown)
- [ ] Architecture diagram (can be a simple mermaid diagram in the README), including the
      desktop app and proxy's place in the system
- [ ] Top-level README tying everything together, with a quickstart
- **Done when:** a fresh clone + `make up && make verify` works from README instructions alone.

## Milestone 23 (stretch) — Payload tester follow-up
- [ ] New package `packages/payload-tester/` that consumes crawler JSON output and fires
      a payload set at discovered forms/params against a newly added intentionally
      injectable target app
- [ ] Own matrix, own `expected_findings.json` style ground truth
- **Done when:** end-to-end pipeline works: crawl → attack-surface JSON → payload tester
      → combined report.
- **Note:** the payload tester must only ever run against local target apps under
  `packages/target-apps/`. Never run it against anything in `docs/05-EXTERNAL-TARGETS.md`.

## Milestone 24 (stretch, lowest priority) — External target smoke tests
- [ ] Read `docs/05-EXTERNAL-TARGETS.md` in full before starting this milestone
- [ ] Add an opt-in flag (e.g. `--allow-external`) that is off by default and never
      touched by `make verify`
- [ ] Smoke-test the crawler (schema-valid output, no crashes, reasonable runtime) against
      a couple of the listed targets — no new `expected_findings.json` ground truth, no
      correctness assertions against them, per the rules in that doc
- **Done when:** running the crawler manually with `--allow-external` against a listed
  target completes cleanly. This milestone should only be picked up after everything
  else (including Milestone 23) is done — it's the lowest priority item in this file.
