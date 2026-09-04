# CLI surface reference (for future UI work)

This is the authoritative list of what the `shroodler` CLI can do, and — for
each capability — whether the desktop app (`packages/desktop-app`) already
wires it up. It exists so a UI developer can see the full product surface
without reverse-engineering `packages/crawler-py/shroodler/cli.py`.

"Wired in desktop" means the Svelte frontend (`App.svelte`) calls the
corresponding Tauri `invoke()` command. Anything marked "CLI-only" has zero
UI today — it works from the terminal or `shroodler-go`/`shroodler-proxy`
directly, but a user of the desktop app cannot reach it.

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

## `shroodler payload <crawl.json>`

**CLI-only in full.** The desktop app has no active-payload-testing surface
at all today — no way to trigger `payload`, choose packs, or view
`payload-*` findings distinctly from passive crawl findings.

| Flag | Purpose |
|---|---|
| `--pack PATH` (repeatable) | load extra YAML pack file/dir alongside the bundled SQLi/XSS/SSTI/path-traversal/SSRF/open-redirect packs |
| `--allow-external` | required to send active payloads to a non-local target |
| `-o/--output` | write findings JSON |

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

Every JSON-producing command (`crawl`, `payload`, `ingest-sessions`)
produces documents validated against [`schema/finding.schema.json`](../schema/finding.schema.json).
That schema is the contract a UI (or any other consumer) should read
against rather than the Python/Go source — it now carries a `schema_version`
field (added to track breaking vs. additive changes) and its `finding.category`
enum includes `payload` (all active-payload-tester findings; the specific
vulnerability class is in `finding.id`, e.g. `payload-sql-error`,
`payload-ssrf`, `payload-open-redirect`) and `scan-note` (non-vulnerability
findings that record an active probe — CORS reflection, GraphQL
introspection — was intentionally skipped because the target wasn't local
and `--allow-external` wasn't passed; treat an empty result differently from
a `scan-note`-flagged skip).
