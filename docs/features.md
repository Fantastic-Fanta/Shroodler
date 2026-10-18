# Features

## Crawl

- **Crawl** — static (HTML parse) or headless (real browser, for SPAs) with
  depth/page/time budgets, robots/sitemap handling, cookie/header/session-state
  injection, configurable `--user-agent`, safe/balanced/aggressive profiles, and
  `--spec` to seed paths from a local OpenAPI/Swagger doc or Postman collection.
- **Scripted login** — re-runs the login recipe up to `--reauth-max-retries`
  times on a mid-crawl 401 or login redirect, then emits `session-died` and stops
  that origin. Recipes may include `oauth_pkce` and opt-in `hook` steps.
- **Go crawl engine** — `shroodler-go` is the sole crawl/network engine (`crawl`,
  `authz-diff`, session-fixation/logout checks, headless). Engine-independent
  analysis (JS, deep extractors, captured-session replay) stays in Python and
  runs on the crawl documents Go emits.
- **Proxy-first hunt** (`crawl --from-capture FILE`) — ingest a HAR / `shroodler
  proxy` JSONL as pages (no re-fetch) and live-crawl only the links and API seeds
  it mentioned. Use with `--proxy` when a WAF challenges the HTML crawler;
  findings from the capture are marked `source=capture`.

## Passive findings

- **Security checks while crawling** — missing security headers, exposed
  secrets/keys, JWT issues (`alg: none`, missing/long expiry, weak secret), CORS
  misconfig, GraphQL introspection, and more.
- **Secret detection** — known-prefix keys plus an entropy heuristic. ASP.NET
  ViewState and benign URL params (`bookmark`, `cursor`, tracking ids) are
  excluded from `generic-api-key`; high-signal names (`api_key`, `secret`, ...)
  still fire.
- **TLS certificate checks** (Python) — expired/expiring, self-signed,
  untrusted-chain (real verified handshake), handshake failures, and
  SAN/CN/IP-SAN hostname mismatch, once per crawl against an `https://` origin.
- **Subresource checks** — cross-origin `<script>`/`<link>` missing SRI, and
  HTTPS pages loading `http://` subresources (mixed content). Go emits these
  during a crawl; `extractors/subresource.py` runs on captured-session replay.
- **Cookie prefix contracts** — `__Secure-`/`__Host-` Set-Cookie violations
  (browsers reject these outright).
- **Auth-stack fingerprinting** — detects next-auth, Keycloak, and Auth0 from
  cookie/path signatures; for next-auth runs the `callbackUrl` probe
  automatically.
- **WAF/bot-mitigation detection** — recognizes Cloudflare/Akamai/PerimeterX/
  DataDome/CAPTCHA challenge pages so the crawler doesn't parse a block page as
  real content; emits `waf-challenge` (vendor as evidence), and
  `waf-challenge-sitewide` when a large share of the crawl was challenged.
  Detection only -- never attempts to solve or bypass a challenge.
- **Confidence-graded findings** (`confirmed` / `probable` / `heuristic`) on
  crawl JSON and payload hits, so the report Confidence column is populated for
  passive checks too. An already-stamped value wins.

## Active payloads

- **Payload testing** — SQLi, XSS, SSTI, path traversal, SSRF, open redirect,
  XXE, OS command injection (marker-echo and blind/timing across shells),
  CRLF/header injection, and PHP stream-wrapper LFI/RFI, including
  blind/out-of-band checks via your own collaborator host.
- **Stored XSS** — after a reflected XSS hit on a POST, a follow-up GET of the
  view page still containing this run's marker is `payload-xss-stored`.

## Access control

- **Authz diff** (`authz-diff`) — replay a higher-privileged crawl's URLs with a
  lower-privileged session to find broken access control.
- **IDOR probing** (`--check-idor`, opt-in) — same-session adjacent-ID replay
  (n-1/n+1) against JSON APIs, proven via matching JSON key shape plus a
  not-found baseline. A medium-severity lead to confirm manually, not a proven
  vuln (one session can't tell whether the adjacent ID is another account).
- **Peer-write replay** (`peer-write`, Python) — replay captured writes against
  known object ids as a second session, with a nonsense-id control and optional
  owner re-read. CSRF tokens are harvested and attached unless `--no-csrf`; a
  captured write with a CSRF field whose harvest fails is skipped (fail closed).
  `--require-confirm` keeps only owner-reread confirmations (default with both
  jars). Jars from Playwright `storageState`, Netscape, HAR, or proxy JSONL.
- **Authenticated CSRF** — `csrf-state-change-unprotected` when a SameSite=None
  session cookie is paired with a state-changing form that has no CSRF field. An
  Origin-reflection probe records a reflected Origin as supporting evidence, not
  proof.

## Auth / session

- **Auth checks** — missing rate limiting on login/auth forms, session fixation,
  logout not invalidating sessions.
- **OAuth 2.0/OIDC checks** — missing/empty `state` (CSRF) and deprecated
  implicit-flow (`response_type=token`) on any crawled authorization URL.
- **OAuth redirect_uri probe** — when Keycloak/Auth0 is fingerprinted, on-origin
  authorize endpoints are probed (CORS-gated) for an open `redirect_uri`
  allowlist (`oauth-redirect-uri-unvalidated`). Confirmed only by a 3xx or
  form_post to `https://shroodler.invalid/oauth-callback`, not an error echo.
- **Token predictability** (`tokens`) — password-reset/verification-token
  analysis from a recorded proxy session. With 2+ samples tests for a sequential
  generator or measures Shannon entropy; with one sample makes only a
  conservative length-based estimate.

## JS analysis

- **JS API surface** — JSON-RPC methods, tRPC procedures, React Query keys, and
  GraphQL operation names mined from JS (`js-jsonrpc-method`, `js-trpc-procedure`,
  `js-react-query-key`, `js-graphql-operation`). React Query and tRPC URLs are
  queued as crawl seeds; `authz-diff` replays GraphQL Query fields
  (`graphql-field-authz`).
- **GraphQL without introspection** — `--gql-schema` / `--gql-wordlist` feed
  Clairvoyance JSON or a field-name list into Query-field replay when live
  introspection is blocked.
- **JS route templates** (`js-routes`) — mine `{userId}`, `{pk}`, `${var}`,
  `:id`, `<int:pk>` URL templates from a bundle so a peer-write playbook has a
  map. Does not fetch or enumerate ids.

## Sessions & capture

- **Session export** (`session-export`) — dump HttpOnly cookies from a live
  Chrome `--cdp` URL (true loopback only unless `--allow-external`), or convert
  HAR / proxy JSONL / Netscape into Playwright `storageState`.
- **Intercepting proxy** (`proxy`) — MITM proxy with its own CA, session
  recording, and AutoResponder-style rules; crawls can route through it or seed
  from a recording.
- **Paced fetch** (`paced-fetch`) — GET/HEAD/OPTIONS a URL list at a capped rate
  (default 1 req/s) so an agent loop doesn't trip rate limits.

## Ingest

- **HAR ingest** (`ingest-har`) — turn a Burp/mitmproxy/Caido/DevTools HAR into
  crawl JSON (pages + passive findings) so `authz-diff`/`payload` can consume
  traffic the proxy never saw. `crawl --seed-from` also auto-detects HAR.
- **Nuclei ingest** (`nuclei-ingest`) — convert local Nuclei HTTP YAML templates
  into payload-pack YAML. Does not download a template library.
- **Slither ingest** (`slither-ingest`) — translate a local Slither JSON report
  into findings. Does not run Slither.
- **SARIF merge** (`report --merge-sarif FILE`) — fold an external SARIF 2.x file
  (Semgrep, CodeQL, Slither, any emitter) into the report, deduped by id+url.

## Reporting & CI

- **Reports** — HTML, CSV, SARIF (GitHub code scanning), JUnit (CI), or Markdown.
  HTML/Markdown carry an executive-summary risk score (0-100, A-F) weighted by
  distinct finding type per severity, so one systemic issue across 500 pages
  doesn't dwarf five distinct critical bugs.
- **Remediation guidance** — every HTML/Markdown finding carries a one-line fix
  (`packages/report-generator/remediation.py`), keyed by finding id.
- **Attack-path** (`attack-path`) — rank findings by clicks from the start URL
  using recorded `edges`. A crawl with no edges falls back to URL path depth (a
  heuristic, flagged as such); an interrupted crawl also lists linked-but-unopened
  URLs (`unfetched`).
- **Chain findings** — `chain-xss-cookie-theft` and `chain-cors-credentialed`
  when both halves exist; a header/SRI issue across many pages collapses to one
  row.
- **Baseline & CI gating** — snapshot findings as a git baseline, then fail CI on
  anything new (`diff --gate`), with suppressions. A suppression can carry an
  `expires` date (after which `diff` warns instead of suppressing) and an `owner`.
- **History & trend** — record scans locally and diff any two (introduced vs.
  resolved, plus same-key severity increases; `trend
  --gate-on-severity-increase`).
- **Tickets** (`ticket file` / `ticket sync`) — open GitHub issues for new
  findings and close them when a later scan no longer reports them. Dry-run by
  default; `--apply` calls `gh`. State in `.shroodler-tickets.json`.
- **Cadence** (`cadence --tier pr|nightly|weekly`) — print recommended
  crawl/payload flags for a slot. Does not itself crawl.

## Agent & memory

- **Engagement memory** (`program`) — per-program state at
  `~/.shroodler/programs/<slug>/state.json` (endpoints tested, object ids,
  findings, sessions). `crawl`/`authz-diff`/`peer-write --program` keep it up to
  date. MCP `program_state` is the orient step; `coverage_gaps` is the untested
  queue.
- **MCP summary output** — `scan_route`, `check_idor`, `peer_write`, and
  `diff_since_baseline` return a compact `{leads, confirmed, probable, top,
  next_step}` dict by default; pass `summary=false` for full JSON.

## Extensibility

- **Triage** (`triage`) — fast pre-crawl pass over a host list or `--discover`
  apex: CT expansion, DNS/CNAME classification (incl. dangling-CNAME takeover),
  and one gentle probe per host labeling redirects, WAF walls, SSO gates, and
  live content. Emits JSON, a table, or a crawl-ready host list. Does not crawl.
- **Plugins** — extra payload packs, secret rules, and optional Python page
  checks from a local directory (`--plugin`, or `$SHROODLER_PLUGIN_PATH`).
