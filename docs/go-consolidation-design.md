# Go consolidation: making crawler-go the primary network engine

Status: design / proposal. Author pass 2026-10-17. Grounded in the current
code and a small empirical benchmark (below). This is a multi-week effort; this
doc is the contract and migration plan, not a finished change.

## Why (and why not "rewrite more in Go")

The ask was "extend Go coverage / make more of the codebase Go." The honest
framing: do NOT broadly port the codebase. Port/consolidate the **network
execution layer** only, and retire the Python duplicates. Everything that is
judgment-heavy or ecosystem-bound stays Python.

The real motivation is **removing duplication**, not a proven speed win. Today
there are two parallel implementations of the crawl/auth/network layer:

| Concern | Python | Go |
|---|---|---|
| crawl | `crawler.py` | `internal/crawler/crawler.go` |
| auth / login | `auth.py` | `internal/crawler/auth.go` |
| sitemap | `sitemap.py` | `internal/crawler/sitemap.go` |
| session checks | `session_checks.py` | `internal/crawler/session_checks.go` |
| authz-diff | `authz_diff.py` | `internal/crawler/authz_diff.go` |
| rate limiting | `rate_limit.py` | `internal/crawler/rate_limit.go` |
| payload dispatch | (in probes) | `internal/payload/tester.go` |

Both are kept in sync by `compare_engines.py` and the `parity-tests` package.
That is a standing tax: every behavior change must land twice and stay
byte-compatible. Consolidating onto one engine removes that tax.

## Empirical findings (small local benchmark)

Benchmarked `shroodler-go crawl` vs `python -m shroodler crawl` against app1
(13 pages, localhost, `--max-pages 100 --depth 5`):

- **Parity holds**: both found the same 21 endpoints.
- Warm wall-clock: Go ~0.10s, Py ~0.51s.
- Of the Python ~0.72s run, **~0.27s is fixed interpreter import/startup**
  (`import shroodler.cli`), the rest is CPU-bound page processing (1.27M calls
  for 13 pages).

Honest reading: on this micro-target the delta is dominated by Python startup,
which Go avoids entirely. That fixed cost matters for short, repeated
invocations and amortizes over long crawls. **The real-world throughput win
(hundreds/thousands of pages, real network latency, concurrent probes) could
NOT be measured here** (no large/latent target, no Docker). Expect the hot path
on real targets to be I/O-bound, where Go buys concurrency, not raw CPU. So:

- Solid, measurable-today justification: **one engine instead of two**.
- Secondary wins: zero startup cost; Go concurrency for high-fan-out operations
  (large crawls, payload replay across many endpoints).
- Unproven until profiled on a real target: per-request speed. Do not oversell it.

## The crux: the agent crawls in-process

`shroodler-go` is today only reached by the standalone `crawl` CLI command and
the compare harness. The **agent loop does not use it** -- `agent_exec._execute_crawl`
calls `crawl_url` from `shroodler.crawler` in-process (agent_exec.py:454), and
the other `_execute_*` executors likewise call Python network modules directly.

So consolidation is not "flip a flag." It requires re-wiring the agent's
execution layer (now conveniently isolated in `agent_exec.py`) to drive the Go
engine over a subprocess + JSON seam and adapt its output into the agent's
`ProgramState` / `Finding` shapes.

## Target architecture

```
+-------------------- Python (shroodler) --------------------+
|  CLI / agent loop / decisions / LLM (llm_agent, provider)  |
|  probes & extractors (heuristics) / triage / reporting     |
|                         |  drives, consumes JSON           |
|             go_engine.py  (subprocess client)              |
+-------------------------|----------------------------------+
                          v  subprocess + JSON (the seam)
+-------------------- Go (shroodler-go) ---------------------+
|  crawl / auth / sitemap / rate-limit / session-checks /    |
|  authz-diff / payload dispatch  (the network engine)       |
+------------------------------------------------------------+
```

- **Go owns**: "send requests fast and safely" -- crawl, auth/login, sitemap,
  rate limiting, session checks, authz-diff, payload/request dispatch.
- **Python owns**: "decide what to send and judge what came back" -- the agent
  loop, all LLM work, probe/extractor heuristics, triage/scoring/impact/chaining,
  report generation, the CLI.
- **The seam**: subprocess invocation of `shroodler-go <subcommand> ... -o -`
  returning JSON on stdout, adapted by a single `go_engine.py` Python module.
  The seam is the stable network boundary, NOT the probe logic (which changes
  constantly and must not be split across languages).

## What moves vs what stays

Move to / consolidate in Go (retire the Python copy):
`crawler.py`, `auth.py`, `sitemap.py`, `session_checks.py`, `authz_diff.py`,
`rate_limit.py`, plus the Python-only network pieces to be ported:
`rest_crawler.py`, the request-dispatch halves of `content_discovery.py` and
`paced_fetch.py` / `pacer.py`.

Stay Python (never move):
`agent*.py`, `llm_*` / `llm_agent/`, all `probes/` and `extractors/`
heuristics, `triage*`, `confidence`, `impact`, `chains`, `attack_*`,
`pentest_report` / `reportgen`, `cli.py` / `commands.py`.

## Migration sequence (incremental, parity-gated)

Each step is independently shippable and keeps the tool working. The Python
engine stays the default until a step is parity-green across all eval apps.

1. **Formalize the seam contract.** Write down the JSON schema `shroodler-go`
   emits for crawl/auth/authz-diff, and add `go_engine.py` (the subprocess
   client) that adapts it to `ProgramState`/`Finding`. Additive, no behavior
   change. Ships to main.
2. **Dual-run in the agent behind a flag.** Add `--engine go` to the agent;
   `_execute_crawl` calls `go_engine` instead of `crawl_url`. Default stays
   `py`. Verify with `compare_engines` + `parity-tests` on all eval apps.
3. **Port the Python-only network pieces** (`rest_crawler`, content-discovery
   dispatch, paced fetch) into `crawler-go`, each with parity tests.
4. **Flip the default to `--engine go`** once parity is green everywhere;
   keep `--engine py` as a fallback for one release.
5. **Retire the Python network modules** (crawler/auth/sitemap/session_checks/
   authz_diff/rate_limit) and the `compare_engines` harness, which exists only
   to keep the two in sync.

## Risks

- **Parity drift = wrong findings.** This is a security tool; a Go/Python
  divergence can silently add or drop findings. `parity-tests` is the gate and
  must stay green through every step; do not retire it until the Python engine
  is gone.
- **Agent coupling.** The agent calls Python network internals in-process today;
  the seam has to cover everything those calls return (not just page lists --
  auth state, cookies, authz-diff results, timing/coverage metadata).
- **Build/CI.** CI already builds Go (crawler-go, proxy-go), but the Python-unit
  job would gain a hard dependency on the `shroodler-go` binary once the agent
  defaults to it. Keep `--engine py` until that is wired.
- **Throughput is unproven.** Do not start the port expecting a big speed win;
  start it to remove duplication. Profile a real target (section F of the
  refactor plan) before promising performance numbers.

## First concrete step

Step 1 (the seam contract + `go_engine.py` adapter) is additive and safe. It is
the right first artifact and can land on main without touching the default
behavior. Everything risky (steps 2-5) rides a feature branch until parity-green.
