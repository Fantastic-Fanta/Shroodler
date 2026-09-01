# Decisions log

Assumptions and deferred items. Newest entries first.

## 2026-09-01 — Tauri version pin

Tauri crates are pinned at `tauri = 2.11.5` and `tauri-build = 2.6.3` (CLI/API 2.11.x).
Pinning `2.1.1` for both pulled a newer `tauri-utils` and failed to compile.

## 2026-09-01 — Desktop + proxy control extras

The proxy spec lists AutoResponder updates over the control channel
(`set_autoresponder_rules`) but not an explicit breakpoint-set or composer message.
`set_breakpoints` and `compose_request` were added so the desktop GUI can drive those
features without editing YAML on disk. Composer still uses the same `ReplaySession`
path as CLI replay.

Desktop `start_scan` with `mode=headless` errors: the shipped sidecar is `shroodler-go`,
which is static-only per architecture.

`accent-rare` is used only for input focus rings.

CA install from the GUI still requires an explicit dialog; the Rust command refuses
`confirmed: false`. macOS Keychain trust may prompt the OS for a password — that is
intentional and not silent.

## 2026-09-01 — Proxy brotli

Bodies with `Content-Encoding: br` are stored as captured bytes; gzip/deflate are
decoded. A brotli decoder was not added as a dependency. Composer is `replay` with
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
