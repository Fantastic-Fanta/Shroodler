# CLI surface reference (for future UI work)

This is the authoritative list of what the `shroodler` CLI can do, and — for
each capability — whether the desktop app (`packages/desktop-app`) already
wires it up. It exists so a UI developer can see the full product surface
without reverse-engineering `packages/crawler-py/shroodler/cli.py`.

"Wired in desktop" means the Svelte frontend (`App.svelte`) calls the
corresponding Tauri `invoke()` command. Anything marked "CLI-only" has zero
UI today — it works from the terminal or `shroodler-go`/`shroodler-proxy`
directly, but a user of the desktop app cannot reach it.

For terminal users (not relevant to a GUI): `--help` on any command, a man
page (`man packages/cli/man/shroodler.1`), and bash/zsh completions
(`packages/cli/completions/`) all exist and are kept in sync with the real
flags by `test_completions_in_sync.py`.

## `shroodler crawl <url>`

Wired in desktop (`invoke("start_scan", …)`), but only a subset of flags are
exposed. Confirm current coverage against `App.svelte` before assuming a
flag is reachable from the UI; the flags below are asserted CLI-only as of
this writing:

| Flag | Purpose | Desktop UI |
|---|---|---|
| `--mode static\|headless` | static HTML parse vs. real browser (SPA) crawl | wired |
| `--allow-external` | scan a non-local host | wired (implied by scan-start dialog) |
| `--depth`, `--max-pages`, `--max-time` | crawl budget controls | **CLI-only** |
| `--ignore-robots`, `--no-sitemap` | discovery-seed behavior | **CLI-only** |
| `--header`, `--cookie`, `--cookie-jar`, `--storage-state` | auth/session context | **CLI-only** (desktop only has ad-hoc cookie/session ingest via `ingest_sessions`) |
| `--login-recipe` | scripted login before crawl | **CLI-only** |
| `--proxy`, `--seed`, `--seed-from`, `--cookies-from` | route crawl through the intercepting proxy / seed from a capture | **CLI-only** |
| `--format` (on crawl output) | inline HTML/CSV/SARIF/JUnit render | **CLI-only** — desktop always stores raw JSON and renders its own views |
| `--profile safe\|balanced\|aggressive` | bundles depth/max-pages/max-time/check-rate-limit into a named preset; explicit flags still override | **CLI-only** |
| `--check-rate-limit` | opt-in: probes discovered login/auth forms for missing rate limiting (real repeated requests — off by default) | **CLI-only** |
| `--login-recipe` fields `logout_url`/`logout_method`/`protected_url` | enables session-fixation and logout-invalidation checks around the existing login flow | **CLI-only** |

## `shroodler payload <crawl.json>`

**CLI-only in full.** The desktop app has no active-payload-testing surface
at all today — no way to trigger `payload`, choose packs, or view
`payload-*` findings distinctly from passive crawl findings.

| Flag | Purpose |
|---|---|
| `--pack PATH` (repeatable) | load extra YAML pack file/dir alongside the bundled SQLi/XSS/SSTI/path-traversal/SSRF/open-redirect/XXE packs |
| `--allow-external` | required to send active payloads to a non-local target |
| `-o/--output` | write findings JSON |
| `--oob-host HOST` | point `{{MARKER_HOST}}` at your own collaborator-style server (self-hosted Interactsh, an `oast.*` instance, or any host you control that logs requests) instead of the non-resolving default placeholder. Enables genuine blind-vuln checks (`blind: true` packs — parameter-entity XXE, OOB SSRF) that are otherwise unverifiable; Shroodler cannot poll your server for you, so check its logs against the token in the output's `oob_probes` list. |

A UI equivalent would need a place to enter/save an OOB host (probably a
project-level setting, not per-scan) and a way to surface `oob_probes`
distinctly from `findings` — they're "sent, unverified" not "confirmed."

## `shroodler authz-diff <higher-priv-crawl.json>`

**CLI-only, and Python-only** (no `shroodler-go` equivalent yet — documented
gap, see the Go-parity note at the end of this file). No desktop surface for
comparing access across two sessions at all. Replays every page URL from a
crawl done under one session (e.g. an admin account) using a second,
lower-privileged session's cookies/headers.

| Flag | Purpose |
|---|---|
| `--cookie name=value` (repeatable) | lower-privilege session's cookie to replay with |
| `--header 'Name: value'` (repeatable) | lower-privilege session's extra header (e.g. an Authorization bearer token) |
| `--no-anon-check` | skip the anonymous control request; report every URL the lower-priv session can reach instead of only ones also denied anonymously |
| `--allow-external` | required for a non-local target |

A UI equivalent would need: pick a "higher-priv" saved scan, pick or enter a
second session's credentials, run, and show `authz-broken-access-control`
(high) vs. `authz-still-accessible` (medium, manual-verify) findings
distinctly from passive ones.

## `shroodler history record` / `shroodler history list` / `shroodler trend`

**CLI-only.** A local, file-based scan history (default
`~/.shroodler/history`, override with `--history-dir`/`$SHROODLER_HISTORY_DIR`)
distinct from the desktop's own `list_scans`/`load_scan` (which store scans
in whatever backing store the Tauri shell uses). `shroodler trend <a> <b>`
diffs findings between any two scans (by history id or file path) —
introduced/resolved (id, url) pairs — which is a different operation from
both `diff --gate` (static-baseline CI gating) and the desktop's
`diff_scans` (compares two scans, but through the desktop's own storage).

If a UI wanted this, the cleanest integration is probably making the
desktop's existing scan storage double as the CLI's `--history-dir`, rather
than building a second history UI from scratch.

This is the single highest-value UI gap: a "Payloads" tab that lets a user
pick packs (with per-pack severity/description shown) and fire them at the
current scan's discovered forms would directly expose an entire capability
category that currently requires dropping to a terminal.

## `shroodler report <findings.json>`

**CLI-only for non-HTML formats.** Desktop renders findings inline; it does
not shell out to generate SARIF/JUnit/CSV/Markdown files a user could
attach to a CI pipeline or bug tracker.

| `--format` | Consumer |
|---|---|
| `html` | human report |
| `csv` | spreadsheet import |
| `sarif` | GitHub code scanning / other SARIF-aware CI |
| `junit` | CI test-result panels |
| `md`/`markdown` | PR descriptions, wikis |

A UI "Export report as…" menu covering these five formats is a small,
high-leverage addition.

## `shroodler diff <findings.json> <expected.json>`

**CLI-only.** This is the CI regression-gate feature (`--gate` fails the
process on any finding not present in the baseline). No desktop equivalent
exists; `diff_scans` in the desktop app compares two *scans* against each
other, which is a different (also useful) operation, not baseline-gating.

| Flag | Purpose |
|---|---|
| `--gate` | non-zero exit if new findings vs. baseline (for CI) |
| `--suppressions` | path to a `.shroodlerignore`-style suppression file |
| `--format text\|junit\|sarif` | CI-consumable diff output |
| `--pages-only` | compare only page coverage, not findings |

## `shroodler baseline` / `shroodler expected` (aliases)

**CLI-only.** Snapshots a scan into an `expected_findings.json` a team
checks into git. No desktop affordance to "accept current findings as
baseline."

## `shroodler ingest-sessions <sessions.jsonl>`

Wired in desktop (`invoke("ingest_sessions", …)`). `--allow-external` and
`--target` overrides may not be exposed in the dialog — check `App.svelte`
before assuming parity.

## `shroodler proxy …`

Partially wired: desktop exposes `start_proxy`, `ca_status`, `install_ca`,
`uninstall_ca`. The full `shroodler-proxy` CLI (session replay, AutoResponder
rule management beyond what's in the editor, arbitrary proxy flags) is
**CLI-only** beyond what those four Tauri commands cover.

## `shroodler version`

Not applicable to a GUI (no desktop equivalent needed).

## Machine-readable output contract

Every JSON-producing command (`crawl`, `payload`, `ingest-sessions`,
`authz-diff`, `trend`) produces documents validated against
[`schema/finding.schema.json`](../schema/finding.schema.json) (`trend`'s
output is its own introduced/resolved shape, not a findings list — see
`history.trend_diff`). That schema is the contract a UI (or any other
consumer) should read against rather than the Python/Go source — it
carries a `schema_version` field (added to track breaking vs. additive
changes) and its `finding.category` enum includes:

- `payload` — all active-payload-tester findings (SQLi/XSS/SSTI/
  path-traversal/SSRF/open-redirect/XXE); the specific vulnerability class
  is in `finding.id` (e.g. `payload-sql-error`, `payload-xxe`).
- `scan-note` — not a vulnerability; records that an active probe (CORS
  reflection, GraphQL introspection) was intentionally skipped because the
  target wasn't local and `--allow-external` wasn't passed. Treat an empty
  result differently from a `scan-note`-flagged skip.
- `auth` — authentication/session/authorization findings that aren't a
  single header or cookie: `missing-rate-limit`, `session-fixation`,
  `logout-session-not-invalidated`, `authz-broken-access-control` /
  `authz-still-accessible`, plus the JWT audit's `jwt-alg-none` /
  `jwt-missing-exp` / `jwt-long-expiry` / `jwt-weak-secret` (JWT findings
  use `secret` category, not `auth`, since they come from the same
  text-scanning pass as the secret-pattern rules).

## Known Go/Python parity gaps

`shroodler-go` mirrors `shroodler` (Python) for `crawl` and `payload`,
including the JWT audit and `--check-rate-limit`. It does **not** yet have
`authz-diff`, the session-fixation/logout-invalidation checks, `history`,
or `trend` — those are CLI/session-flow orchestration built only in Python
so far. If Go parity matters for a given deployment, check
`packages/crawler-go/cmd/shroodler/main.go`'s subcommand list before
assuming feature parity with the Python CLI's `--help` output.
