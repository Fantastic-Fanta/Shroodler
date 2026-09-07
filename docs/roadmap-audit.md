# Roadmap audit

Maps every idea in `docs/roadmap.md` to **DONE**, **PARTIAL**, **NOT-STARTED**,
or **DEFER**. First written 2026-09-07; statuses below reflect the build
pass that followed (commits on `main`, local only). Multi-year protocol
breadth is still DEFER.

Status key:

- **DONE** — shipped as a CLI/MCP command or module a user can actually
  invoke. Cite the surface.
- **PARTIAL** — a real slice exists; the remaining gap is listed.
- **NOT-STARTED** — no command/module yet.
- **DEFER** — out of scope for this pass (multi-year, ambiguous, or
  already-covered-enough). Left for the maintainer.

## Agent / AI compatibility

| Idea | Useful | Status | Where / what's missing |
|---|---|---|---|
| MCP server (`scan_route`, `check_idor`, `diff_since_baseline`, `explain_finding`) | 5 | **DONE** | `shroodler mcp-server` → `packages/mcp-server`. `--help` names the tools; `--list-tools` prints the catalog. |
| Agent-driven confirmation of "manual confirmation required" IDOR leads | 5 | **DONE** | `authz-diff --higher-priv-marker` / `--lower-priv-marker` / `--require-identity-confirmation`; MCP `check_idor` takes the same markers. |
| Closed-loop remediate-and-reverify | 5 | **DONE** | `shroodler reverify` + MCP `reverify_fix`. `gen-regression-test` is the non-agent close of the same loop. |
| Conversational interrogation of scan/report/history | 4 | **DONE** | `shroodler ask` (`packages/crawler-py/shroodler/ask.py`). |
| LLM-generated/adapted payload mutation | 4 | **DONE** | `payload --adaptive` (one extra enforcer-gated mutation per pack miss; never `confidence=confirmed`). Tight enough; not expanding live generation. |
| Guardrail/safety layer for agentic active-payload testing | 5 | **DONE** | `packages/guardrails` (consent manifest, operator-clamped rate ceilings, hash-chained audit log). Wired into `payload`/`authz-diff`/`reverify` and default-on for MCP active tools. `audit-verify` checks the chain. |

## Session-driven ideas

| Idea | Useful | Status | Where / what's missing |
|---|---|---|---|
| Scope triage sweep (`shroodler triage`) | 4 | **DONE** | `shroodler triage` (`packages/crawler-py/shroodler/triage.py`). Bounded concurrency/rate, proxy-aware, WAF-polite, `--header`/`--user-agent`, `--no-active`, local-only by default. |
| Auth-stack fingerprinting + standard probe library | 4 | **DONE** | `extractors/auth_stack.py` during crawl. next-auth `callbackUrl` probe; Keycloak/Auth0 fingerprint-only. |
| Reduce URL-embedded-token false positives in entropy secret detector | 3 | **DONE** | `extractors/secrets.py`: benign query names (`bookmark`, `cursor`, tracking IDs) skip `generic-api-key`; high-signal names still fire. |

## Closing the gap with ZAP

| Idea | Useful | Status | Where / what's missing |
|---|---|---|---|
| Plugin/extension API for checks (payload packs, secret rules) | 5 | **DONE** | `packages/crawler-py/shroodler/plugins.py`; `--plugin` / `$SHROODLER_PLUGIN_PATH` on `crawl` and `payload`. |
| Protocol coverage breadth (WebSockets, gRPC, SOAP, deeper GraphQL, OpenAPI/HAR import) | 4 | **DEFER** | Multi-year catch-up. GraphQL introspection and OpenAPI discovery during crawl exist; HAR ingest is `ingest-sessions`; local OpenAPI/Postman *seed* is the separate `--spec` item (DONE). Do not build WS/gRPC/SOAP. |
| Authenticated-scan ergonomics (auto re-auth on session expiry, multi-role beyond two-session diff) | 4 | **PARTIAL** | Mid-crawl re-auth shipped (`--login-recipe` re-runs once on 401/login-redirect). Multi-role beyond two-session `authz-diff` remains **DEFER**. |
| CVE-signature/template library | 3 | **DONE** | Loader only: `shroodler nuclei-ingest` + `payload --pack` auto-detect. Not a Nuclei-scale template collection (that stays DEFER). |

## Workflow / CI-native originality

| Idea | Useful | Status | Where / what's missing |
|---|---|---|---|
| Findings-as-code diff, code-attributed (URL → route → source file) | 5 | **DONE** | `diff --source-root` (`packages/crawler-py/shroodler/code_attribution.py`). Flask/FastAPI/Express/Django heuristics + `git log -L` blame. |
| Per-finding ownership + SLA | 4 | **DONE** | `shroodler sla apply` (`sla.py`); suppression `owner`/`expires` already existed. |
| Dual-engine differential as a confidence signal | 3 | **DONE** | `shroodler compare-engines`. |
| Confidence-graded findings (marker vs timing vs heuristic, sortable column) | 4 | **DONE** | Payload tester stamps match-clause confidence; crawl JSON now stamps passive checks via `shroodler/confidence.py` (`confirmed`/`probable`/`heuristic`). |
| Cost-of-attack weighting | 4 | **DONE** | `packages/report-generator/cost_of_attack.py`; reports already emit the axis. |
| Minimal-repro payloads | 3 | **DONE** | Payload tester prefers the shortest same-or-higher-confidence match and stamps `minimal_repro: true`. |
| Auto-generate a regression test from a confirmed-then-fixed finding | 4 | **DONE** | `shroodler gen-regression-test`. |
| Auto-filed tickets from new findings | 4 | **DONE** | `shroodler ticket file` / `ticket sync` (`tickets.py`). Dedup by id+path; dry-run default; `--apply` calls `gh`. |
| Scheduled suppression-expiry PRs | 3 | **DONE** | `shroodler suppress expiring --format github-pr-body` (renders a PR body; the scheduled job that opens it is the operator's). |
| Tiered scan cadence packaged as a template | 3 | **DONE** | `shroodler cadence --tier pr\|nightly\|weekly` prints recommended flags; does not scan. |
| Auto-discover scan scope from OpenAPI/Postman spec | 3 | **DONE** | In-crawl `/openapi.json` probe plus `crawl --spec FILE` for a local OpenAPI/Swagger or Postman collection. |

## More speculative

| Idea | Useful | Status | Where / what's missing |
|---|---|---|---|
| Attack-path graph report | 5 | **DONE** | `shroodler attack-path`. Path-depth heuristic (not a persisted link graph — documented). |
| Adversarial self-scan | 3 | **DONE** | `shroodler self-scan`. |
| WAF-coverage regression as a first-class finding | 3 | **DONE** | `trend --gate-on-waf-coverage-drop`. |
| Target-published consent/scope manifest | 3 | **DONE** | `packages/guardrails` + `--require-policy` / `--policy-file` / `--audit-log`. |

## This pass

Buildable queue — all shipped in this pass unless DEFER:

1. Audit doc (this file).
2. `shroodler triage`
3. Plugin/extension API + MCP `--help` / `--list-tools`
4. Code-attributed diff — already DONE; no rebuild.
5. Auth-stack fingerprinting
6. Confidence-graded findings gap-fill
7. Auto-filed tickets
8. Authenticated-scan auto re-auth (multi-role still DEFER)
9. URL-embedded-token FP reduction
10. OpenAPI/Postman `--spec` seed
11. `shroodler cadence`
12. Nuclei YAML ingest (loader only)

## Explicitly not building (still DEFER)

- WebSockets / gRPC / protobuf / SOAP / WS-Security / "deeper GraphQL".
- Multi-role context switching beyond the existing two-session `authz-diff`.
- A Nuclei-scale CVE *library* (ingest-the-format only).
- Expanding `--adaptive` into free-form LLM live-payload generation.

## Ambiguous / skipped-with-note

- **Attack-path "real link-graph traversal"** — `attack-path` already ships a documented path-depth heuristic because neither crawler persists a graph. Building a real graph would mean a crawler storage change; skipped rather than guessed.
- **Scheduled suppression-expiry PRs that actually open a PR** — the command already emits a GitHub PR body for a CI job to consume. Wiring `gh pr create` into the tool would take a token and a default repo we don't have; left as operator glue.
- **`ticket --apply` against real GitHub** — unit tests inject a fake backend; dry-run is the default. Operators who pass `--apply` need a working `gh`.
