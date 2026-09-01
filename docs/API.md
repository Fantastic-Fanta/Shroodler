# Module map

Generated from package layout (docstrings live in source).

## crawler-py (`shroodler`)

- `crawler.Crawler` / `crawl_url` — static or Playwright crawl
- `extractors.*` — forms, headers, cookies, secrets, JS endpoints, common paths
- `cli` — `shroodler crawl|diff|report`
- `--header` / `--cookie` / `--cookie-jar` — extra request headers and cookie-jar auth
- `--allow-external` — off by default; required for hosts outside loopback/`.local`

## crawler-go

- `internal/crawler.Crawl`
- `internal/extractors` — same YAML rule-pack as Python
- `cmd/shroodler` — CLI parity with Python (no headless)

## proxy-go

- `internal/proxy.Server` — HTTP(S) capture, breakpoints, AutoResponder, replay
- `internal/ca` — local root CA under `SHROODLER_PROXY_HOME`
- Control channel `ws://127.0.0.1:8890/control`

## desktop-app

Tauri v2 shell. Sidecars only: `shroodler-go`, `shroodler-proxy`. Finding JSON is never re-derived in the UI.

## payload-tester

Reads crawler JSON and submits a small payload set at discovered forms. Local targets only.
