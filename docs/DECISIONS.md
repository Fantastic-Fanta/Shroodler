# Decisions log

Assumptions and deferred items. Newest entries first.

## 2026-09-01 — Extra crawl headers and cookies

`--header 'Name: value'` is repeatable and attached to every crawler HTTP request
(static `httpx` / `net/http`, including robots, login POST, path probes, and source
maps). `--cookie name=value` fills the crawl cookie jar so the Cookie header is sent
on every request; later `Set-Cookie` of the same name wins. `.shroodlerrc` keys
`header` and `cookie` are lists with the same values as the flags.

Python headless passes both via Playwright (`extra_http_headers` + `add_cookies`).
Go headless Chrome navigations get `--header` through CDP `SetExtraHTTPHeaders` and
`--cookie` through `network.SetCookie`. Same-origin and `--allow-external` are
unchanged. App1 `/lab-gated` is an unlinked test-only page gated by `lab_auth=open`
or `X-Lab-Auth: open`.

## 2026-09-01 — Authenticated crawl + desktop headless

Cookie jar is a crawl-time jar, not a new schema. `--login-recipe` is a small JSON
file (`url` + `fields`); hidden inputs are merged from a GET so app1's CSRF token
does not have to be copied by hand. Desktop headless prefers the Python Playwright
crawler (repo `.venv` or `SHROODLER_PY_BIN`) because `make bootstrap` already
installs Chromium; if that binary is missing, `shroodler-go --mode headless` uses
chromedp against system Chrome. Packaged Tauri builds still need one of those
browsers on the machine — we do not ship CPython or Chrome in the app bundle.

Go headless click enumeration is best-effort (Evaluate a small click script). Python
Playwright remains the coverage path for SPA button-only routes.

## 2026-09-01 — Closed documented holes

JS source maps: both crawlers follow `sourceMappingURL` (relative, same-origin, or
inline `data:`) and extract endpoints/secrets from `sourcesContent`, attributing the
original file in evidence (`src/internal.ts`). Fixture: app1 `static/mapped.min.js`.

Proxy `Content-Encoding: br` bodies are stored decoded via `andybalholm/brotli`.
CONNECT MITM against httptest TLS, CA-missing 502, and breakpoint resume/drop/edit
are covered. CLI `main` in both Go binaries delegates to `run([]string) int` so
usage/unknown-command paths are tested without `os.Exit`.

Desktop `start_scan` with `mode=headless` prefers the Python crawler when `.venv` /
`SHROODLER_PY_BIN` exists, then `shroodler-go --mode headless` (chromedp + system
Chrome, `CHROME_PATH` override). Tests skip when Chrome is not installed; the Go CLI
returns a non-zero error instead of rejecting the mode.

## 2026-09-01 — Crawl stats and expected_findings generator

Optional top-level `stats` (`pages_crawled`, `requests`, `elapsed_ms`) is emitted by both
crawlers. It is not in `required`, so scans written before this field still validate.
`requests` counts fetcher round-trips (page GETs, robots, probes, source maps, retries);
headless page navigations count as one request each, not every browser subresource.
Python and Go totals will not match — probe lists, retry timing, and login POSTs differ.

Parity (`parity-tests/run_parity.py`) already compares page paths and finding `id+path`
pairs only. `stats` is excluded from that comparison the same way timestamps and
`crawler.version` are. Do not fail parity because elapsed_ms or request counts differ.

`shroodler expected` is an alias of `shroodler baseline`. It maps a scan to
`expected_pages` / `expected_forms` / `expected_findings` and leaves `expected_not_found`
empty. Humans add negatives; the generator must not invent them.

## 2026-09-01 — Data-driven packs

Secret patterns, common-path wordlists, and payload-tester packs are data files both
engines load. New cloud keys went into `secret-patterns/rules/cloud.yaml`. Path probes
are every `wordlists/*.txt`, not a single hardcoded list. Payload strings and detect
signatures live in `payload-tester/packs/*.yaml`; the engines only implement the matcher
(`status_gte` / `body_contains` / `reflected`). Fixtures (app1 JS leaks, app1 git HEAD /
security.txt / id_rsa, app3 `.env` GitHub PAT, app5 SQLi/XSS/SSTI/traversal) plus
`expected_findings.json` are the ground truth.

The desktop inspector still uses a JS snapshot of the original eight secret rules for
opt-in body scan — crawlers remain the source of truth. Probed path bodies are now
secret-scanned so a token in `/.env` is not only `exposed-file`.

## 2026-09-01 — Crawler ↔ proxy fusion

Sidecars still do not import each other. Fusion is `--proxy`, session JSONL
(`ingest-sessions`, `--seed-from`, `--cookies-from`), and `--cookie`. Ingest is
passive (no common-path probe). Last captured response per canonical URL wins.
Cookie jar is origin-scoped; later `Set-Cookie` overwrites the same name.
`crawler.mode` gained `ingest`. Desktop ingest writes JSONL and shells out to
`shroodler-go ingest-sessions`.

## 2026-09-01 — Lab workflow (baseline / gate / suppressions)

`shroodler diff` stays fixture-mode by default so existing target-app tests still require
every `expected_findings` row. `--gate` is the productized CI mode for any local app:
new `id+path` pairs fail, disappeared pairs print as `resolved` and do not fail. That
matches "this snapshot is the accepted surface" rather than "the crawler must still see
the planted vulns."

`.shroodlerignore` is YAML (`suppressions: [{id, url, reason}]`), not a gitignore dialect,
so it matches secret-patterns / AutoResponder. `url` globs treat `*` as matching slashes.

SARIF/JUnit are report renderers; they do not change `finding.schema.json`. Desktop Map /
export buttons convert the already-loaded document rather than adding sidecar crawl flags.

## 2026-09-01 — Milestone 21 coverage

`crawler-py` unit tests measure **92%** (`pytest --cov=shroodler`). CONNECT MITM,
breakpoint resume, and CLI `run()` paths are tested. `make cover` still reports Go
internal package percentages; `make verify` does not fail the tree on a Go 90% shortfall.

## 2026-09-01 — Tauri version pin

Tauri crates are pinned at `tauri = 2.11.5` and `tauri-build = 2.6.3` (CLI/API 2.11.x).
Pinning `2.1.1` for both pulled a newer `tauri-utils` and failed to compile.

## 2026-09-01 — Desktop + proxy control extras

The proxy spec lists AutoResponder updates over the control channel
(`set_autoresponder_rules`) but not an explicit breakpoint-set or composer message.
`set_breakpoints` and `compose_request` were added so the desktop GUI can drive those
features without editing YAML on disk. Composer still uses the same `ReplaySession`
path as CLI replay.

Desktop `start_scan` with `mode=headless` prefers Python Playwright, then Go chromedp.

`accent-rare` is used only for input focus rings.

CA install from the GUI still requires an explicit dialog; the Rust command refuses
`confirmed: false`. macOS Keychain trust may prompt the OS for a password — that is
intentional and not silent.

## 2026-09-01 — Proxy brotli

Bodies with `Content-Encoding: gzip/deflate/br` are stored decoded. Composer is `replay` with
an empty originating session (CLI `shroodler-proxy replay`).

Backends listen on 127.0.0.1:8085/8086 and are only reached through the gateway
on :8084. The crawler stays same-origin, so multi-service recon is via gateway
paths (`/users`, `/orders`) plus JS `fetch` endpoints, not by crawling backend
origins directly.

The `generic-api-key` YAML rule uses a sentinel pattern `__ENTROPY__` so both
language implementations can special-case the heuristic without hardcoding other
patterns in crawler source.

`enctype`, `disabled`, and `readonly` are optional in the spec. The schema allows
`null` so crawlers can omit a value without dropping the key inconsistently.

- Pagination traps are detected only for `/page/<n>` paths and `page=` query params,
  not every numeric path segment (so depth tests like `/p/10` still work).
- `shroodler diff --pages-only` exists so page-discovery can pass before extractors
  populate findings.
- Rate-limit tests use `Retry-After: 0` to stay fast.

`/usr/local/bin/docker` is a broken symlink to Docker.app, which is not installed.
`make up` / `make verify` use a local process fallback (`scripts/local-up.sh`) that
binds the same ports (8081–8084) on 127.0.0.1. Docker Compose files remain the
canonical container path for machines that have Docker.

## 2026-09-01 — Milestone 1 dashboard cookie vs session gate

Unauthenticated `GET /dashboard` returns 200 with a login-wall body and still sets
`session_id` (Secure=false). Full dashboard content remains session-gated. This lets
the crawler observe the insecure-cookie finding without posting credentials.

## 2026-09-01 — Milestone 0 scaffolding

- Docs originally lived in the repo root. Moved into `docs/` to match `01-ARCHITECTURE.md`.
- Hostnames `app1.local` … `app4.local` are Docker network aliases. Host-side tests use `http://127.0.0.1:8081` (and 8082/8083/8084) so we do not require `/etc/hosts` changes. Spec examples that show `app1.local` are illustrative.
- `finding.schema.json` includes optional `enctype` on forms and optional `disabled`/`readonly` on fields so later extractor milestones do not require a schema bump. `same_site` may be `null` when the attribute is absent.
- Milestone 0 `make verify` is a stub (`echo "no tests yet"`) as the architecture allows. Real checks land as later milestones add them.
