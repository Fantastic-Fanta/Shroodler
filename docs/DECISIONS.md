# Decisions log

Assumptions and deferred items. Newest entries first.

## 2026-09-01 — Milestone 2 crawler defaults

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
