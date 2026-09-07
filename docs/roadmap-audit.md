# Roadmap audit

Maps every idea in `docs/roadmap.md` to **DONE**, **PARTIAL**, **NOT-STARTED**,
or **DEFER**. Written 2026-09-07 after reading the CLI surface (`shroodler
--help` and each subcommand's `--help`), `packages/`, and the existing
docs. Multi-year protocol-breadth work is DEFER and will not be built in
this pass.

Status key:

- **DONE** — shipped as a CLI/MCP command or module a user can actually
  invoke. Cite the surface.
- **PARTIAL** — a real slice exists; the gap is listed so this pass can
  fill it or skip it with a reason.
- **NOT-STARTED** — no command/module yet. Buildable items are queued
  below.
- **DEFER** — out of scope for this pass (multi-year, ambiguous, or
  already-covered-enough). Left for the maintainer.

## Agent / AI compatibility

| Idea | Useful | Status | Where / what's missing |
|---|---|---|---|
| MCP server (`scan_route`, `check_idor`, `diff_since_baseline`, `explain_finding`) | 5 | **PARTIAL** | `shroodler mcp-server` → `packages/mcp-server` (`scan_route`, `check_idor`, `reverify_fix`, `diff_since_baseline`, `explain_finding`). `--help` is bare (no flags, no tool list) — polish queued. |
| Agent-driven confirmation of "manual confirmation required" IDOR leads | 5 | **DONE** | `authz-diff --higher-priv-marker` / `--lower-priv-marker` / `--require-identity-confirmation`; MCP `check_idor` takes the same markers. |
| Closed-loop remediate-and-reverify | 5 | **DONE** | `shroodler reverify` + MCP `reverify_fix`. `gen-regression-test` is the non-agent close of the same loop. |
| Conversational interrogation of scan/report/history | 4 | **DONE** | `shroodler ask` (`packages/crawler-py/shroodler/ask.py`). |
| LLM-generated/adapted payload mutation | 4 | **DONE** | `payload --adaptive` (one extra enforcer-gated mutation per pack miss; never `confidence=confirmed`). Tight enough; not expanding live generation this pass. |
| Guardrail/safety layer for agentic active-payload testing | 5 | **DONE** | `packages/guardrails` (consent manifest, operator-clamped rate ceilings, hash-chained audit log). Wired into `payload`/`authz-diff`/`reverify` and default-on for MCP active tools. `audit-verify` checks the chain. |

## Session-driven ideas

| Idea | Useful | Status | Where / what's missing |
|---|---|---|---|
| Scope triage sweep (`shroodler triage`) | 4 | **NOT-STARTED** | No command. Spec in `docs/roadmap.md` is complete — **first build item**. |
| Auth-stack fingerprinting + standard probe library | 4 | **NOT-STARTED** | No next-auth/Keycloak/Auth0 detector or `callbackUrl` probe. OAuth checks (`extractors/oauth.py`) are a different, URL-query-only check. |
| Reduce URL-embedded-token false positives in entropy secret detector | 3 | **NOT-STARTED** | ASP.NET ViewState is already excluded (`extractors/secrets.py`); query-param names (`bookmark=`, `cursor=`, tracking IDs) still trip `generic-api-key`. |

## Closing the gap with ZAP

| Idea | Useful | Status | Where / what's missing |
|---|---|---|---|
| Plugin/extension API for checks (payload packs, secret rules) | 5 | **NOT-STARTED** | `payload --pack` loads extra YAML packs one path at a time; secret rules are baked into `packages/secret-patterns/rules`. No plugin directory / discovery / Python check hook. Foundational — queued right after triage. |
| Protocol coverage breadth (WebSockets, gRPC, SOAP, deeper GraphQL, OpenAPI/HAR import) | 4 | **DEFER** | Multi-year catch-up. GraphQL introspection and OpenAPI *discovery during crawl* already exist; HAR ingest exists as `ingest-sessions`. Do not build WS/gRPC/SOAP. OpenAPI/Postman *as a seed input* is a smaller, separate item below. |
| Authenticated-scan ergonomics (auto re-auth on session expiry, multi-role beyond two-session diff) | 4 | **PARTIAL** | Login recipe + cookie/header injection + `authz-diff` two-session replay exist. Missing: mid-crawl re-auth on 401/login-redirect. Multi-role beyond two sessions is **DEFER** (catch-up, unclear UX). Auto re-auth is queued. |
| CVE-signature/template library | 3 | **NOT-STARTED** | Roadmap says ingest Nuclei YAML rather than compete on library size. Queued as a loader, not a template collection. |

## Workflow / CI-native originality

| Idea | Useful | Status | Where / what's missing |
|---|---|---|---|
| Findings-as-code diff, code-attributed (URL → route → source file) | 5 | **DONE** | `diff --source-root` (`packages/crawler-py/shroodler/code_attribution.py`). Flask/FastAPI/Express/Django heuristics + `git log -L` blame. |
| Per-finding ownership + SLA | 4 | **DONE** | `shroodler sla apply` (`sla.py`); suppression `owner`/`expires` already existed. |
| Dual-engine differential as a confidence signal | 3 | **DONE** | `shroodler compare-engines`. |
| Confidence-graded findings (marker vs timing vs heuristic, sortable column) | 4 | **PARTIAL** | Payload tester already stamps `confidence` (`confirmed`/`probable`/`heuristic`); HTML/MD/CSV reports already show the column. Crawl-time (passive) findings do not get a confidence, so the column is empty for most of a crawl report. Gap-fill queued. |
| Cost-of-attack weighting | 4 | **DONE** | `packages/report-generator/cost_of_attack.py`; reports already emit the axis. |
| Minimal-repro payloads | 3 | **DONE** | Payload tester prefers the shortest same-or-higher-confidence match and stamps `minimal_repro: true`. |
| Auto-generate a regression test from a confirmed-then-fixed finding | 4 | **DONE** | `shroodler gen-regression-test`. |
| Auto-filed tickets from new findings | 4 | **NOT-STARTED** | `diff --gate` only fails a build. No issue-file/sync command. |
| Scheduled suppression-expiry PRs | 3 | **DONE** | `shroodler suppress expiring --format github-pr-body` (renders a PR body; the scheduled job that opens it is the operator's). |
| Tiered scan cadence packaged as a template | 3 | **NOT-STARTED** | Profiles (`safe`/`balanced`/`aggressive`) exist; no PR/nightly/weekly packaging. Mostly docs + a tiny command. |
| Auto-discover scan scope from OpenAPI/Postman spec | 3 | **PARTIAL** | Crawl already probes `/openapi.json` etc. and seeds paths from a fetched spec. No `--spec` flag to *import* a local OpenAPI or Postman collection as crawl seeds. |

## More speculative

| Idea | Useful | Status | Where / what's missing |
|---|---|---|---|
| Attack-path graph report | 5 | **DONE** | `shroodler attack-path`. Path-depth heuristic (not a persisted link graph — documented). |
| Adversarial self-scan | 3 | **DONE** | `shroodler self-scan`. |
| WAF-coverage regression as a first-class finding | 3 | **DONE** | `trend --gate-on-waf-coverage-drop`. |
| Target-published consent/scope manifest | 3 | **DONE** | `packages/guardrails` + `--require-policy` / `--policy-file` / `--audit-log`. |

## Sequencing for this pass

Buildable queue (skip DONE; DEFER stays unbuilt):

1. **`shroodler triage`** — spec is the point; operational constraints are required.
2. **Plugin/extension API** + **MCP `--help` polish** (foundational).
3. Code-attributed diff — already DONE; no rebuild.
4. Remaining NOT-STARTED / PARTIAL by Useful, then Original:
   1. Auth-stack fingerprinting (4/4)
   2. Confidence-graded findings gap-fill (4/3)
   3. Auto-filed tickets (4/2)
   4. Authenticated-scan auto re-auth (4/1) — the buildable slice
   5. URL-embedded-token FP reduction (3/2)
   6. OpenAPI/Postman spec seed (3/2)
   7. Tiered scan cadence template (3/2)
   8. Nuclei YAML ingest (3/1)

## Explicitly not building

- WebSockets / gRPC / protobuf / SOAP / WS-Security / "deeper GraphQL" (DEFER).
- Multi-role context switching beyond the existing two-session `authz-diff` (DEFER).
- A Nuclei-scale CVE *library* (DEFER; ingest-the-format only).
- Expanding `--adaptive` into free-form LLM live-payload generation (DONE enough; risk).
- Rebuilding MCP / guardrails / reverify / ask / sla / compare-engines / self-scan / attack-path / gen-regression-test / code-attribution / cost-of-attack / minimal-repro / consent-manifest / WAF-coverage trend / suppression-expiry PRs.

## Ambiguous / skipped-with-note

- **Attack-path "real link-graph traversal"** — `attack-path` already ships a documented path-depth heuristic because neither crawler persists a graph. Building a real graph would mean a crawler storage change; skipped rather than guessed.
- **Scheduled suppression-expiry PRs that actually open a PR** — the command already emits a GitHub PR body for a CI job to consume. Wiring `gh pr create` into the tool would take a token and a default repo we don't have; left as operator glue.
