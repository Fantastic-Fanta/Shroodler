# Features

- **Nuclei ingest** (`shroodler nuclei-ingest`) — converts local Nuclei
  HTTP YAML templates into payload-pack YAML. `payload --pack` also
  auto-detects a Nuclei-shaped file. Does not vendor or download a
  template library.

- **Cadence** (`shroodler cadence --tier pr|nightly|weekly`) — prints
  recommended crawl/payload flags for a PR-time passive scan, a nightly
  active scan, or a weekly aggressive+adaptive scan. Does not itself
  crawl.

- **Tickets** (`shroodler ticket file` / `ticket sync`) — open GitHub
  issues for new findings (the same id+path key `diff --gate` uses) and
  close them when a later scan no longer reports the finding. Dry-run by
  default; `--apply` calls `gh`. Dedup state lives in
  `.shroodler-tickets.json`.

- **Confidence-graded findings** (`confirmed` / `probable` /
  `heuristic`) on crawl JSON as well as payload hits, so the report
  Confidence column is populated for passive checks too: header/cookie/
  TLS observations are `confirmed`, IDOR/authz leads are `probable`,
  entropy `generic-api-key` and auth-stack fingerprints are `heuristic`.
  An already-stamped value (payload tester, authz identity marker) wins.

- **Triage** (`shroodler triage`) — a fast pre-crawl pass over a host
  list or `--discover` apex: passive Certificate Transparency expansion,
  DNS/CNAME classification (including dangling-CNAME takeover
  candidates), and one gentle HTTP probe per live host that labels
  redirect aliases, WAF/challenge walls, SSO/auth gates, and live
  unauthenticated content. Bounded concurrency + rate, proxy-aware,
  WAF-polite (pauses a zone on challenge/429), identifying User-Agent
  and required custom headers. Emits JSON, a table, or a crawl-ready
  host list (`--format hosts` / `--hosts-out`). Does not crawl or fire
  payloads.
- **Secret detection** — known-prefix keys plus an entropy heuristic,
  with ASP.NET ViewState and known-benign URL query params (`bookmark`,
  `cursor`, tracking IDs) excluded from `generic-api-key` so they don't
  drown real leaked tokens. High-signal query names (`api_key`,
  `secret`, ...) still fire.
- **Auth-stack fingerprinting** — detects next-auth, Keycloak, and Auth0
  from cookie/path signatures during a crawl, and for next-auth runs the
  known `callbackUrl` → callback-url-cookie probe automatically.
- **Plugins** — extra payload packs, secret rules, and optional Python
  page checks loadable from a local directory (`--plugin` on `crawl` /
  `payload`, or `$SHROODLER_PLUGIN_PATH`).
- **Crawl** — static (HTML parse) or headless (real browser, for SPAs)
  crawling with configurable depth/page/time budgets, robots/sitemap
  handling, scripted login (re-runs the login recipe once if a mid-crawl
  fetch returns 401 or a login redirect), cookie/header/session-state
  injection,
  configurable User-Agent (`--user-agent`), named safe/balanced/
  aggressive profiles, and `--spec` to seed extra same-origin paths from
  a local OpenAPI/Swagger document or Postman collection.
- **Cookie prefix contracts** — `__Secure-`/`__Host-` Set-Cookie
  violations (browsers reject these outright), distinct from the
  existing "could adopt a prefix" suggestions.
- **Passive findings** — missing security headers, exposed secrets/keys,
  JWT issues (`alg: none`, missing/long expiry, weak secret), CORS
  misconfig, GraphQL introspection, and more, discovered while crawling.
- **WAF/bot-mitigation detection** — recognizes Cloudflare/Akamai/
  PerimeterX/DataDome/CAPTCHA challenge and interstitial pages (via
  response headers, body wording, and known challenge-issuance cookies)
  so the crawler doesn't silently parse a block page as real target
  content (a `waf-challenge` finding is emitted instead, with the vendor
  as evidence). A single same-URL retry is attempted after a challenge
  cookie is issued, to recover transient challenges without solving
  anything. When a large share of the crawl was challenged, a single
  `waf-challenge-sitewide` finding flags that the scan's other results
  substantially understate the target's real surface. Detection only —
  Shroodler never attempts to solve or bypass a challenge; ask the
  target's operator to allowlist the scan if this fires unexpectedly.
- **Active payload testing** — SQLi, XSS, SSTI, path traversal, SSRF,
  open redirect, XXE, OS command injection (marker-echo and blind/timing
  variants across `;`/`|`/`&&`/backtick/`$()`/Windows shells), CRLF/HTTP
  header-injection, and PHP stream-wrapper LFI/RFI (rot13-proof file
  read, data:// wrapper RCE), including blind/out-of-band checks via your
  own collaborator host.
- **TLS certificate checks** (Python-only for now) — expired/expiring-soon
  certs, self-signed certs, untrusted-chain (real verified-handshake
  check, catches non-self-signed certs from a CA nothing trusts), TLS
  handshake failures, and SAN/CN/IP-SAN hostname mismatch, checked once
  per crawl against an `https://` target's origin.
- **Subresource checks** (always on, Python-only for now) — cross-origin
  `<script>`/`<link>` tags missing Subresource Integrity, and HTTPS pages
  loading `http://` subresources (mixed content). `shroodler-go` doesn't
  implement this yet; `packages/parity-tests/run_parity.py` excludes the
  `subresource` finding category from its Python/Go comparison rather
  than this being gated behind an opt-in flag.
- **Remediation guidance** — every finding in the HTML and Markdown
  reports carries a one-line fix suggestion (`packages/report-generator/
  remediation.py`), keyed by finding id with a category-level fallback for
  ids added by new payload/secret packs.
- **Auth checks** — missing rate limiting on login/auth forms, session
  fixation, logout not invalidating sessions.
- **Authz diff** — replay a higher-privileged crawl's URLs with a
  lower-privileged session to find broken access control.
- **IDOR probing** (`--check-idor`, opt-in) — same-session adjacent-ID
  replay against JSON API endpoints (n-1/n+1), proven via matching
  top-level JSON key shape plus a not-found-baseline probe to rule out
  targets that don't distinguish valid/invalid IDs at all. Reported as a
  medium-severity lead to manually confirm (a single session can't tell
  whether the adjacent ID belongs to a different account), not a proven
  vulnerability.
- **Peer-write replay** (`shroodler peer-write`, Python-only) — replay
  captured writes against *known* object ids as a second session, with a
  nonsense-id control and an optional owner re-read. A dummy 200 that
  matches the fake id, or `{"success": false}`, is not a finding. This
  is not an enumerator and does not invent adjacent ids. Cookie jars
  come from Playwright `storageState`, Netscape, HAR, or proxy JSONL —
  no crawl required. MCP: `peer_write`.
- **JS route templates** (`shroodler js-routes`) — mine `{userId}`,
  `{collectionId}`, `{pk}`, `${var}`, `:id`, and `<int:pk>` URL
  templates from a webpack/SPA bundle so a peer-write playbook has a
  map. Does not fetch or enumerate ids. MCP: `extract_js_routes`.
- **Paced fetch** (`shroodler paced-fetch`) — GET/HEAD/OPTIONS a URL
  list at a capped rate (default 1 req/s) so an agent loop does not
  trip a program's rate limit. Does not solve captchas. MCP:
  `paced_fetch` (max 20 URLs).
- **OAuth 2.0/OIDC checks** (both engines) — missing/empty `state` param
  (CSRF risk) and deprecated implicit-flow (`response_type=token`)
  detection on any crawled authorization-request URL.
- **`shroodler tokens`** — password-reset/verification-token
  predictability analysis from a recorded proxy session (a token is
  delivered out-of-band, so this is a standalone command over captured
  JSONL, not a crawl-time check). With 2+ samples of the same token
  parameter, tests for a sequential/incrementing generator or measures
  real Shannon entropy across the samples; with a single sample, only
  makes a conservative length-based estimate and says so explicitly.
- **Intercepting proxy** — MITM proxy with its own CA, session recording,
  and an AutoResponder-style rule system; crawls can route through it or be
  seeded from a recorded session.
- **History & trend** — record scans locally and diff findings between any
  two of them (introduced vs. resolved, plus same-key severity
  increases; `trend --gate-on-severity-increase` for CI).
- **Baseline & CI gating** — snapshot current findings as a baseline
  checked into git, then fail CI on anything new (`diff --gate`), with
  optional suppressions. A suppression can carry an `expires` date
  (YYYY-MM-DD): once passed, the rule stops suppressing and `diff`
  warns (not fails) that it aged out, rather than silently suppressing
  forever with no visible signal. An optional `owner` field is carried
  through for humans/tooling.
- **Reports** — render findings as HTML, CSV, SARIF (GitHub code scanning),
  JUnit (CI test panels), or Markdown. HTML and Markdown carry an
  executive-summary risk score (0-100, A-F) weighted by distinct
  finding type per severity (not raw per-page instance count, so one
  systemic header issue repeated across 500 pages doesn't dwarf five
  genuinely distinct critical bugs on one page).
- **Two crawler implementations** — a Python crawler (full feature set) and
  a Go crawler (`shroodler-go`, faster, same core subcommands including
  `authz-diff` and session-fixation/logout-invalidation checks). A few
  features are Python-only for now (subresource/SRI checks, headless
  mode); `packages/parity-tests/run_parity.py` excludes known
  Python-only finding categories from its comparison rather than
  requiring the two engines to be feature-identical before either can
  ship a check.
