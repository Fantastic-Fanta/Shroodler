# Decisions log

Assumptions and deferred items. Newest entries first.

## 2026-09-01 — Milestone 0 scaffolding

- Docs originally lived in the repo root. Moved into `docs/` to match `01-ARCHITECTURE.md`.
- Hostnames `app1.local` … `app4.local` are Docker network aliases. Host-side tests use `http://127.0.0.1:8081` (and 8082/8083/8084) so we do not require `/etc/hosts` changes. Spec examples that show `app1.local` are illustrative.
- `finding.schema.json` includes optional `enctype` on forms and optional `disabled`/`readonly` on fields so later extractor milestones do not require a schema bump. `same_site` may be `null` when the attribute is absent.
- Milestone 0 `make verify` is a stub (`echo "no tests yet"`) as the architecture allows. Real checks land as later milestones add them.
