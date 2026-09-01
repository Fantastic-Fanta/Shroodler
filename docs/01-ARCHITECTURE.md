# Architecture

## Overview

Shroodler is a monorepo containing:
- A crawler + attack-surface extractor, implemented twice (Python first, Go port second)
- A family of intentionally vulnerable target apps used purely as test fixtures
- A shared JSON schema that both implementations must produce identical output against
- A report generator (JSON → HTML/CSV)
- A CLI that wraps everything
- A rule-pack package for secret-detection patterns, versioned independently

## Repo layout

```
shroodler/
├── Makefile                      # top-level `make verify`, `make up`, `make down`
├── docker-compose.yml            # spins up all target apps + any services
├── docs/
│   ├── 00-PROMPT.md
│   ├── 01-ARCHITECTURE.md
│   ├── 02-SPEC.md
│   ├── 03-TEST-MATRIX.md
│   └── 04-MILESTONES.md
├── schema/
│   ├── finding.schema.json       # JSON Schema, source of truth for crawler output shape
│   └── proxy-session.schema.json # JSON Schema for captured proxy sessions
├── packages/
│   ├── crawler-py/
│   │   ├── shroodler/
│   │   │   ├── crawler.py
│   │   │   ├── extractors/
│   │   │   │   ├── forms.py
│   │   │   │   ├── headers.py
│   │   │   │   ├── cookies.py
│   │   │   │   ├── secrets.py
│   │   │   │   ├── js_endpoints.py
│   │   │   │   └── common_paths.py
│   │   │   ├── modes/
│   │   │   │   ├── static.py     # requests + BeautifulSoup
│   │   │   │   └── headless.py   # Playwright
│   │   │   └── report.py
│   │   ├── tests/
│   │   │   ├── unit/
│   │   │   └── integration/
│   │   └── pyproject.toml
│   │
│   ├── crawler-go/
│   │   ├── cmd/shroodler/main.go
│   │   ├── internal/
│   │   │   ├── crawler/
│   │   │   ├── extractors/
│   │   │   └── report/
│   │   ├── tests/
│   │   └── go.mod
│   │
│   ├── parity-tests/             # runs py + go against same target, diffs output
│   │   └── run_parity.py
│   │
│   ├── secret-patterns/          # versioned rule-pack (its own semver + changelog)
│   │   ├── rules/*.yaml
│   │   └── tests/
│   │
│   ├── report-generator/         # JSON -> HTML/CSV, shared by both crawlers
│   │   ├── templates/
│   │   └── tests/
│   │
│   ├── target-apps/
│   │   ├── app1-server-rendered/   # Flask/Express, forms + sessions
│   │   ├── app2-spa/               # React SPA, fetch-driven content
│   │   ├── app3-crawler-traps/     # infinite pagination, redirect loops, honeypots
│   │   └── app4-microservices/     # gateway + 2-3 backend services
│   │
│   ├── cli/
│   │   ├── shroodler_cli/
│   │   └── tests/
│   │
│   ├── proxy-go/                  # Fiddler-style intercepting proxy, own binary
│   │   ├── cmd/shroodler-proxy/main.go
│   │   ├── internal/
│   │   │   ├── proxy/             # capture engine, TLS interception
│   │   │   ├── ca/                # root CA generation, per-host leaf certs
│   │   │   ├── breakpoint/
│   │   │   ├── autoresponder/
│   │   │   └── control/           # WebSocket control channel
│   │   ├── tests/
│   │   └── go.mod
│   │
│   └── desktop-app/               # Tauri v2 + Svelte GUI, wraps shroodler-go and
│       │                          # shroodler-proxy as sidecars
│       ├── src/                   # Svelte frontend
│       ├── src-tauri/             # Rust shell — sidecar orchestration, IPC, no scan/proxy logic
│       └── tests/
│
└── .github/workflows/ci.yml      # optional, mirrors `make verify`
```

## Tech stack

- **Python** (`crawler-py`): `httpx`, `BeautifulSoup4`/`lxml`, `playwright`, `pytest`,
  `hypothesis` for property-based/fuzz tests, `pydantic` for schema validation.
- **Go** (`crawler-go`): standard `net/http`, `golang.org/x/net/html`, `go test`,
  `go-fuzz` or native `testing.F` fuzzing (Go 1.18+ built-in fuzzing is fine).
- **Target apps**: mix it up on purpose — Flask for app1, React+Vite for app2, Express
  for app3, and a small Go or Node gateway for app4. This forces the crawler to handle
  real heterogeneity, not just one framework's quirks.
- **Report generator**: plain Jinja2 templates (Python) is enough; keep it simple.
- **Orchestration**: Docker Compose brings up all four target apps on fixed ports/hosts
  so tests are deterministic.
- **Desktop app** (`desktop-app`): Tauri v2 (Rust shell) + Svelte frontend. Ships the Go
  crawler binary (`shroodler-go`) and the Go proxy binary (`shroodler-proxy`) as sidecar
  processes — Go compiles to a single static binary, which is what makes both embeddable
  in an app bundle; Python is not shipped inside the desktop app. Visual design follows
  `docs/06-UI-STYLE.md`.
- **Proxy engine** (`proxy-go`): Go, standard `net/http` plus `crypto/tls`/`crypto/x509`
  for on-the-fly certificate generation (root CA + per-host leaf certs), a WebSocket
  library (e.g. `nhooyr.io/websocket` or `gorilla/websocket`) for the control channel. See
  `docs/07-PROXY-SPEC.md` for the full contract.

## Package boundaries — rules

1. `crawler-py` and `crawler-go` never import from each other. They only share the
   JSON schema (`schema/finding.schema.json`) and the target apps as fixtures.
2. `secret-patterns` is consumed by both crawlers as a data file (YAML), not code —
   keeps the rule-pack language-agnostic.
3. `report-generator` takes crawler JSON output as input and knows nothing about how
   it was produced.
4. `target-apps/*` have zero dependencies on anything else in the repo — they must be
   able to run standalone via `docker compose up app1`.
5. `parity-tests` is the only package allowed to import/invoke both crawlers.
6. `desktop-app` only ever talks to `shroodler-go` as an external sidecar process via its
   CLI contract (`02-SPEC.md` section 3) and reads/writes finding JSON that already
   validates against `schema/finding.schema.json`. It must not reimplement or duplicate
   any crawling, extraction, or secret-detection logic — if the GUI needs a capability the
   CLI doesn't expose yet, add it to the CLI/spec first, then consume it from the app.
7. `proxy-go` is independent from `crawler-go` and `crawler-py` — it does not import
   either, and they don't import it. It may load `secret-patterns` YAML the same way the
   crawlers do (data, not code). `desktop-app` manages it as a second sidecar, talking to
   it only via the control channel/CLI defined in `docs/07-PROXY-SPEC.md`.

## The verification loop

`make verify` should run, in order:
1. Lint (both languages)
2. Unit tests (both languages)
3. `docker compose up -d` (all target apps)
4. Integration tests: each crawler against each target app, diffed against that app's
   `expected_findings.json`
5. Schema validation of all produced JSON against `schema/finding.schema.json`
6. Parity check: py output vs go output on the same target, structurally diffed
   (ignoring timestamps/ordering)
7. `docker compose down`

Exit non-zero on any failure. This is the command Cursor should run after every
milestone and paste the output of.
