# Changelog

All notable changes to Shroodler are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project has
not yet made a versioned PyPI release, so entries below are grouped by the
work that produced them rather than tags.

## Unreleased

- **Wider OpenAPI probe coverage.** Spec-discovered endpoints now also get open-redirect and CRLF probes (previously only SQLi/XSS/traversal/IDOR/unauth), so a redirect param reached only via the spec is no longer missed. Found by the eval harness: planted-bug recall on a local lab went 75% → 100%.
- **LLM autoconfirm (`--llm-verify`).** After a deterministic `shroodler agent`
  scan, the LLM verifier re-checks each tentative (heuristic/probable) finding
  against fresh evidence and confirms, downgrades, or drops it as a false
  positive — the same verification the `--llm-agent` loop runs at report time,
  now available without the full agent. Opt-in; requires a provider key and
  uses `--llm-provider` / `--llm-reasoning-model`.
- **Baseline-differential SQLi.** Error-based SQL injection now confirms only
  when the database error is absent from a clean baseline request, so a
  persistent error page (or a param that always errors) no longer produces a
  false positive. The other injection probes were already context-aware:
  SSTI confirms only on evaluated math, path traversal on a real file marker,
  open-redirect/CRLF on the actual response header, SSRF on an OOB callback
  (reflection stays heuristic).

- **Content-type-aware XSS.** The reflected/stored XSS probes now confirm
  High/Critical only when the response actually renders as HTML (text/html,
  xhtml, svg, or an undeclared type a browser may sniff). A payload reflected
  verbatim in a JSON API response is not executable, so it now reports as
  `xss-reflected-nonhtml` / `xss-stored-nonhtml` (Low, heuristic) with a note to
  check for second-order HTML rendering, instead of a false High. Cuts a real
  false positive seen against a FastAPI JSON endpoint.

- **Guessable capability-identifier detection (logic bug, no LLM).** Flags a resource reached by a short opaque capability code (share/invite/export/preview) whose keyspace is small enough to enumerate — e.g. a 6-hex `token_hex(3)` code, a 24-bit space. Reads the identifier from the URL, estimates entropy from length and charset, and reports only when the endpoint returns data; numeric ids (IDOR's job) and word slugs are ignored. Runs autonomously in the ProbeAction and OpenAPI probe paths.
- **SPA API discovery.** Both JS extractors (`js_analyzer.py` agent path,
  `extractors/js_endpoints.py` crawl path) now pull bare API-path string
  literals (`/api/…`, `/rest/…`, `/graphql`, `/v1/…`) out of minified bundles,
  not just paths inside a recognized `fetch()`/`axios` call. Modern SPAs store
  the path as a constant and call it through a variable, which defeated the
  old call-syntax matchers. Restricted to API-ish prefixes to avoid pulling in
  static assets. On a real Vite SPA this took endpoint discovery from 0 to 26.
- **Two new detection probes.** `rate-limit-bypass-forwarded-for`: after a
  fixed-client burst throttles, a second burst rotating `X-Forwarded-For`
  per request that never throttles proves the limiter keys on the spoofable
  header (auth brute-force bypass); High. `unauthenticated-data-exposure`: a
  user-scoped/sensitive API path (`/me`, `/messages`, `/guild`, `/admin`, …)
  that returns 200 structured data with no credentials is flagged as broken
  access control; High, confidence probable. Both run in the agent's probe loop
  (`--no-…` via config); the second one caught a real live unauthenticated
  `/api/guilds` leak in testing.

- **Measuring "smarter": evaluation harness.** `shroodler eval <scan> <expected>`
  scores a run against curated ground truth — precision, recall, F1, plus LLM
  cost and iteration count when present — matching on `(id, url-path)` like
  `diff --gate`. `--baseline` A/Bs two runs (LLM tools off vs on) and prints the
  delta. Scoring lives in `shroodler/eval_harness.py`; `make eval-agent` and
  `packages/crawler-py/eval/README.md` drive it against the local target apps.
- **Auto-verify before reporting.** The LLM agent now runs evidence-based
  verification on every tentative finding before `report()`, confirming,
  re-scoring, or dropping false positives without depending on the planner to
  ask. Bounded by the run's cost cap; disable with `--no-auto-verify`.
- **Hypothesis chaining.** `test_hypothesis` pops the top pending hypothesis
  (from `analyze_logic` / `hypothesise`), translates it into one concrete
  in-scope test, runs it under the scope guardrail, and records the outcome
  (validated / inconclusive) so the planner stops re-suggesting it. Only an
  allowlist of concrete tools can be planned, and the target must pass scope.
- **Cross-engagement memory.** Fingerprint facts learned during a run (WAF
  vendor, ID scheme, JWT algorithm, GraphQL presence) persist on program state
  and surface to the planner on the next run as a KNOWN FACTS block, so a repeat
  engagement starts already knowing the target's shape. Facts are non-secret and
  reinforced across runs.

- **Smarter LLM agent: reads results and reasons on evidence.** The agent loop
  now feeds a structured `LAST OBSERVATION` (status, timing, where input
  reflected, a body snippet) back to the planner each turn, so decisions follow
  the evidence instead of a one-line summary. New planner tools:
  `send_request` (craft and send any HTTP request, then read the result),
  `compare_responses` (diff two requests, e.g. price tampering),
  `replay_as_user` (owner vs peer vs anonymous, for broken access control),
  `decode_token` (inspect a JWT/base64, flag `alg:none`/HMAC),
  `craft_payloads` (the model writes payloads tailored to observed stack
  details and this layer fires and scores them), `verify_finding` (re-fetch a
  finding and have the model confirm it, adjust its confidence, or drop it as a
  false positive), and `analyze_logic` (reason about business-logic abuse —
  price/param tampering, coupon reuse, step-skipping, IDOR chains — and queue
  hypotheses). All target-controlled text is wrapped in `<untrusted_data>` and
  the planner is told never to follow instructions inside it; the scope
  guardrail (now covering nested request specs) remains the hard backstop.
- **DeepSeek is the default provider.** `shroodler agent --llm-agent` defaults
  to `deepseek` / `deepseek-chat` (the cheapest option); high-volume planning
  and triage run on the cheap model, while `verify_finding` and `analyze_logic`
  escalate to a stronger reasoning model, configurable via
  `--llm-reasoning-model` (default `deepseek-reasoner`). Pass
  `--llm-provider anthropic` to use Claude. Auxiliary LLM calls count toward the
  existing `--llm-agent-max-cost` cap.

- **REST-aware agent authz.** `shroodler agent` sends `Authorization: Bearer`
  from `--owner-cookie` / `--peer-cookie` on authz-diff instead of only jar
  cookies. `--write-authz-spec` replays POST/PATCH/DELETE probes as both
  principals (lower-priv 2xx is a confirmed finding). Three consecutive
  zero-page crawls skip further CrawlActions so API-first targets reach
  authz-diff.

- **Discovery pipeline + LLM triage.** `shroodler discover --program <slug>
  --target <url>` finds live subdomains via crt.sh and new JS API endpoints,
  then merges them into program state. `--dry-run` reports counts with no
  writes. `shroodler agent --run-discovery` runs this before the loop;
  `--llm-triage` ranks unconfirmed leads with Claude Haiku (falls back to
  the existing order when `ANTHROPIC_API_KEY` is missing or the call
  fails). MCP tools `discover_scope` and `run_agent` (`llm_triage`,
  `run_discovery`) expose the same surface. `discover_scope` is an active
  tool and uses the scan-policy rate ceiling.

- **Autonomous agent loop.** `shroodler agent --program <slug> --target <url>`
  reads program state, crawls stale/un-crawled endpoints, runs authz-diff
  and peer-write when session jars/cookies are provided, then reports
  confirmed findings. `--dry-run` prints the plan with no requests. MCP
  tool `run_agent` returns `{iterations, confirmed, log}`.

- **Auth hardening.** `--login-recipe` re-runs up to `--reauth-max-retries`
  (default 3) times on a mid-crawl 401 or login redirect, with exponential
  backoff (1s, 2s, 4s). If every retry fails, crawl emits a high
  `session-died` finding (last good URL + request count) and stops that
  origin instead of continuing with a dead session. Login recipes gain
  `oauth_pkce` (token endpoint → `Authorization: Bearer`) and opt-in
  `hook` steps (arbitrary command from a trusted recipe, e.g. Castle.io
  token fetch).

- **MCP summary output.** `scan_route`, `check_idor`, `peer_write`, and
  `diff_since_baseline` default to compact `{leads, confirmed, probable,
  top, next_step}` instead of raw JSON (`summary=false` for the full
  blob). `next_step` is a plain-English instruction for the agent.

- **Engagement memory.** `shroodler program` (`init` / `status` / `merge` /
  `add-session`) stores per-program state at
  `~/.shroodler/programs/<slug>/state.json`. `crawl --program`,
  `authz-diff --program`, and `peer-write --program` / `--from-program`
  update coverage and object IDs. MCP tools `program_state` and
  `coverage_gaps` return a compact briefing for the agent's orient step.

- **CSRF harvest fail-closed.** If a captured write already carried a
  CSRF field/header and a fresh token cannot be harvested, `peer-write`
  skips the write (`csrf-missing`) instead of sending a tokenless POST.
  Stale JSON/header tokens are replaced, not kept. `payload` harvests
  CSRF on write methods, never fuzzes CSRF-named fields, and skips a
  form that required a token when harvest fails (`--no-csrf` disables).

- **`session-export --cdp` loopback-only.** DevTools URLs must be true
  loopback (`127.0.0.1` / `::1` / `localhost`) unless `--allow-external`.
  `http(s)` only; userinfo, empty host, `*.local`, and `0.0.0.0` are
  refused. `/json/version` is fetched with redirects disabled and the
  `webSocketDebuggerUrl` is pinned to the same loopback port before
  Playwright connects. `--origin` must be an absolute http(s) URL when
  set. MCP `session_export` always requires `origin`; `cdp`/`from`
  require `policy_file` or `allow_without_policy` (this tool does not
  GET `.well-known/scan-policy.json`). Cookie names/values with
  CR/LF/`;` are dropped.

- **Authenticated CSRF Origin probe.** After `csrf-state-change-unprotected`,
  crawl sends an anonymous OPTIONS to the write action with
  `Origin: https://evil.example` (CORS-gated, no GET, cookies stripped).
  A reflected Origin is attached as supporting evidence. Findings only
  emit for same-origin http(s) actions (no `javascript:`, userinfo, or
  off-origin forms).

- **Two-jar confirm by default.** `peer-write` with both owner and peer
  jars keeps only owner-reread confirmations (`run()` itself, not only
  the CLI wrapper). `--allow-unconfirmed` emits probable leads.
  `--require-confirm` without an owner jar now errors. Verify URLs are
  same-origin GET/HEAD only (no off-origin cookie leak; POST write URLs
  are not GETed unless the playbook names a view). Owner `confirmed`
  requires both before and after 2xx. Captured `Authorization` headers
  are not replayed as the peer. Nonsense-id no-ops are skipped. Stored
  XSS needs this run's token on a follow-up GET whose body differs from
  the POST.

- **JS API seeds.** React Query keys and tRPC procedure names found in JS
  are queued as same-origin crawl URLs (`/api/...`, `/trpc/...`). Protocol-
  relative keys, `..`, and control characters are rejected; `--depth`
  applies to API enqueue.

- **Compound chains.** `chain-xss-cookie-theft` requires a session cookie
  without HttpOnly on the same origin. `chain-cors-credentialed` requires
  CORS origin reflection with `ACAC=true` plus SameSite=None session
  cookie. Header clustering is per origin.

- **`--from-capture`.** Captures are capped at 20 MiB / 400 ingested
  pages / 200 follow-up URLs. Captured request URLs are not re-fetched
  (canonical-key match). Live robots.txt, sitemap, and OpenAPI probe
  URLs are skipped. Findings from ingest are marked `source=capture`.
  Zero same-origin ingested pages emit `capture-no-same-origin-sessions`
  instead of failing silently.

- **OAuth `redirect_uri` probes.** Keycloak/Auth0 on-origin authorize
  GETs are anonymous. A finding requires a 3xx Location whose host/path
  is `https://shroodler.invalid/oauth-callback`, or a 200 HTML form
  whose action is that URL (`response_mode=form_post`). An error-page
  echo of the marker is not a finding. Realm names come from the URL
  path only; Auth0 fingerprinting uses the hostname, not the query
  string. Authorize URLs are joined from the origin, not the seed path.

- **`crawl --from-capture FILE`.** Ingest HAR/JSONL pages without
  re-fetching them; live-crawl only follow-up links and API seeds. Pair
  with `--proxy` when a WAF blocks the HTML crawler.

- **OAuth `redirect_uri` allowlist probe.** On-origin Keycloak/Auth0
  authorize endpoints are probed (CORS-gated) with
  `redirect_uri=https://shroodler.invalid/oauth-callback`.

- **`shroodler ingest-har`**: turn a Burp / mitmproxy / Caido / DevTools
  HAR 1.2 export into crawl JSON (Page records + passive findings from
  captured bodies). `ingest-sessions` and `crawl --seed-from` /
  `--cookies-from` also auto-detect HAR. Does not re-fetch the target.

- **`--gql-schema` / `--gql-wordlist`** on `crawl` and `authz-diff`: feed
  Clairvoyance JSON or a plain field-name wordlist into GraphQL Query
  field replay when live introspection is blocked. Crawl records the
  names on discovered GraphQL endpoints; `authz-diff` consumes them
  (or takes the flags itself). MCP `check_idor` accepts the same.

- **`shroodler slither-ingest`**: translate a local Slither JSON report
  into Shroodler findings. A loader, not an EVM analyzer.

- **`report --merge-sarif FILE`**: fold an external SARIF 2.x file
  (Semgrep, CodeQL, Slither, any SARIF emitter) into the report.
  Dedupes by id+url against findings already in the crawl JSON.

- **CSRF harvest on writes.** `peer-write` GETs the origin (or `--csrf-from`)
  and attaches a token from a hidden input, meta tag, JS global, or cookie
  as `X-CSRF-Token` / form / JSON fields. `--no-csrf` disables it. A
  CSRF-shaped 403 retries once after a refresh.

- **`shroodler session-export`**: write a Playwright `storageState` JSON
  from `--cdp` (Chrome `--remote-debugging-port`), a HAR / proxy JSONL /
  Netscape jar, or `--cookie` pairs. The file is what
  `--owner-cookies-from` / `--peer-cookies-from` already accept. MCP:
  `session_export`.

- **Authenticated CSRF finding** (`csrf-state-change-unprotected`): a
  SameSite=None session cookie plus a state-changing form with no CSRF
  field. Lax cookies are not flagged.

- **Confirmed peer-write.** Owner re-read defaults to GET the write URL
  when `--owner-cookie` is set. `--require-confirm` drops leads the
  owner re-read did not change. Stored XSS: after a reflected XSS hit on
  a POST, a follow-up GET of the view page that still contains the marker
  is `payload-xss-stored`.

- **JS API surface.** Crawl extracts JSON-RPC methods, tRPC procedures,
  React Query keys, and GraphQL operation names from JS (`js-jsonrpc-method`,
  `js-trpc-procedure`, `js-react-query-key`, `js-graphql-operation`).
  `authz-diff` replays GraphQL Query fields as the lower-priv session
  (`graphql-field-authz`).

- **Chain findings + clustered headers.** Reports emit
  `chain-xss-cookie-theft` and `chain-cors-credentialed` when both halves
  are present, and collapse a header/SRI issue repeated on 8+ pages to
  one row.

- **`shroodler peer-write`**: replay captured POST/PUT/PATCH/DELETE
  requests against *known* object ids as a second session. Each write is
  also sent to a nonsense id — the same 200 as the fake id is
  dummy-success, not a finding; `success: false` is a write-failure. A
  peer 2xx that differs from the control is `peer-write-idor`; an owner
  re-read that changed upgrades it to confirmed. Not n±1 enumeration.
  Accepts a playbook JSON, HAR, or proxy JSONL (`--from-sessions`) plus
  Playwright `storageState` / Netscape / JSONL cookie files. Default
  1 req/s. MCP tool `peer_write`.

- **`shroodler js-routes`**: extract `{userId}` / `{pk}` / `:id` /
  `<int:pk>` URL templates from a local JS bundle. Templates only — does
  not fetch or enumerate ids. MCP tool `extract_js_routes`.

- **`shroodler paced-fetch`**: GET/HEAD/OPTIONS a URL list at a capped
  rate (default 1 req/s) so agent/Playwright loops do not stampede a
  1-req/s program. Does not solve captchas. MCP tool `paced_fetch`
  (cap 20).

- **`shroodler nuclei-ingest`**: convert local Nuclei HTTP YAML templates
  into a payload pack. `payload --pack` also auto-detects a Nuclei-shaped
  file. A loader, not a CVE library — does not download templates.

- **`shroodler cadence --tier pr|nightly|weekly`**: prints recommended
  crawl/payload flags for a PR-time passive scan, a nightly active
  scan, or a weekly aggressive+adaptive scan. Packaging only; does not
  scan. Weekly still omits `--allow-external`.

- **`--spec` crawl seed.** `crawl --spec FILE` imports a local
  OpenAPI/Swagger document or Postman collection and enqueues same-origin
  paths as extra seeds (in addition to the existing in-crawl
  `/openapi.json` probe). Off-origin URLs in a Postman collection are
  dropped.

- **Authenticated-scan auto re-auth.** With `--login-recipe`, a mid-crawl
  401 or login redirect re-runs the recipe once and retries that URL.
  Further expiry in the same crawl is not retried. 403 is left alone
  (authorization, not session death).

- **`shroodler ticket file` / `ticket sync`**: turn new findings into
  GitHub issues (deduped by the same id+path key as `diff --gate`) and
  close them when a later scan no longer reports the finding. Dry-run
  by default; `--apply` is required to invoke `gh`. `--owners` assigns;
  local state is `.shroodler-tickets.json`.

- **Confidence-graded findings** on crawl JSON. Passive checks now stamp
  `confidence` (`confirmed` / `probable` / `heuristic`) so reports no
  longer show an empty Confidence column for a crawl. Header/cookie/TLS
  observations are confirmed; IDOR/authz leads are probable; entropy
  `generic-api-key` and auth-stack fingerprints are heuristic. Payload
  tester and authz identity-marker stamps are left alone.

- **URL-embedded-token false-positive reduction** for `generic-api-key`.
  A long opaque value that appears only as a query-string parameter named
  something known-benign (`bookmark`, `cursor`, `session`, tracking ids,
  ...) is no longer flagged as a leaked key -- the City of Vienna
  `bookmark=` map-link case. A high-signal name (`api_key`, `secret`,
  `access_token`, ...) in a URL still fires, and a token that also
  appears outside a query string still fires.

- **Auth-stack fingerprinting + next-auth callbackUrl probe.** Crawl now
  detects next-auth / Keycloak / Auth0 from cookie and path signatures
  and, for next-auth, GETs `/api/auth/signin?callbackUrl=` with a marker
  host to see whether the unvalidated URL is written into the
  callback-url cookie -- the check that previously had to be rebuilt from
  memory against each next-auth target. Keycloak/Auth0 are fingerprint
  only for now. Same local-only / `--allow-external` gate as CORS.

- **Plugin/extension API** for extra payload packs, secret rules, and
  optional Python `check()` hooks, loadable via `crawl --plugin` /
  `payload --plugin` or `$SHROODLER_PLUGIN_PATH`. A directory with
  `plugin.yaml` is the explicit form; a bare dir of YAML files is
  classified by shape. Plugins are trusted local operator code, not
  remote content.
- **`shroodler mcp-server --help` / `--list-tools`**: the MCP subcommand
  was a bare parser with no flags and no tool list. `--help` now names
  every tool (`scan_route`, `check_idor`, `reverify_fix`,
  `diff_since_baseline`, `explain_finding`); `--list-tools` prints the
  catalog (descriptions + input schemas) as JSON and exits.

- **`shroodler triage`**: a fast, low-touch pre-crawl pass that turns a
  host list (and/or `--discover` apex / `*.wildcard`) into a ranked,
  classified table -- dead, dangling-CNAME takeover candidate,
  third-party SaaS, redirect-alias, WAF-challenge-gated, SSO/auth-gated,
  or live unauthenticated content -- so crawl/payload budget goes only
  to hosts worth it. Discovery is passive (Certificate Transparency);
  the only contact with a target is one HTTP probe per live host,
  skippable with `--no-active`. Concurrency and request rate are bounded
  and clamped (never an unbounded fan-out); a local egress proxy is
  detected and drops default parallelism; a WAF challenge or 429 pauses
  the rest of that zone. `--header` / `--user-agent` cover per-program
  required identifiers. Local-only by default.

- **Fixes from a pentester/CI-reviewer pass on the suppression-expiry
  feature.** The core mechanism (expiry reaching the real `diff --gate`
  enforcement path, boundary date handling, `date.min` fail-safe) held
  up under review, but the edges around it didn't:
  - **`shroodler baseline` regenerated over an expired suppression with
    no warning**, silently baking the now-unsuppressed finding in as
    freshly-accepted, unattributed risk -- exactly backwards for a
    mechanism meant to force periodic re-review, not quietly become
    permanent. The expiry warning is now shared (`_warn_expired_
    suppressions`) and printed by every command that loads
    suppressions: `diff`, `baseline`, `report`, `trend`.
  - **The warning claimed "no longer suppressing"** even when a
    broader rule (a wildcard `id="*"`/`url="*"`, which a mature
    `.shroodlerignore` tends to accumulate) still covered the same
    finding -- reworded to the claim actually supported ("this rule no
    longer applies; another rule may still cover the finding").
  - **`"expires": ""` (present but empty) was treated the same as the
    key being absent** (never expires) via a truthiness check --
    silently disabling the feature for a rule whose value got cleared
    out or misconfigured. Presence vs. absence of the key is now
    checked explicitly; a present-but-invalid value fails safe to
    already-expired, like an unparseable one always did.
  - Whitespace around a date (`" 2099-01-01 "`) no longer fails to
    parse. The warning now says explicitly when a value was
    unparseable (vs. a real, on-schedule expiry) and includes `owner`/
    `reason` -- `owner` existed purely for accountability and wasn't
    printed anywhere.
- **Suppression rules can now carry an `expires` date**
  (`packages/crawler-py/shroodler/suppress.py`). A rule with
  `"expires": "YYYY-MM-DD"` stops suppressing once that date has
  passed -- `diff` (in any mode, including `--gate`) prints a warning
  naming the expired rule rather than silently continuing to suppress
  forever, or the finding it hides silently going unsuppressed with no
  visible signal either way. A rule with no `expires` field behaves
  exactly as before (never expires) -- fully backward compatible with
  every existing `.shroodlerignore`. An unparseable `expires` value
  fails safe (treated as already-expired, surfaced as a warning) rather
  than silently suppressing forever because a date was typo'd. Rules
  also gained an optional `owner` field, carried through for humans/
  tooling. Pure post-processing over already-produced JSON, so this
  never touches `crawl` and has no Python/Go parity surface.
- **Fixes from a pentester review of the cookie-prefix-violation checks
  and the trend severity gate -- the headless false positive was
  disqualifying on its own.**
  - **Every `__Host-` cookie in a headless crawl false-positived, in
    both engines, 100% of the time, once per page.** Headless mode
    doesn't read raw Set-Cookie headers -- it synthesizes header-shaped
    strings from the browser's cookie jar API, which never exposes
    Path/Domain. Treating an absent Path/Domain as violation evidence
    under those conditions flagged every `__Host-` cookie, including
    ones a real browser demonstrably accepted and stored, with wording
    that asserted the opposite of what actually happened
    ("browsers reject this Set-Cookie entirely"). `extract_cookies()`/
    `ExtractCookies()` now take an `attrs_reliable`/`attrsReliable` flag
    (false in headless mode, threaded through `page_from_fetch`/
    `pageFrom`): the Secure-flag check (which the jar API *does* report
    reliably) still runs, but the Domain-presence and Path-exactness
    checks are skipped when the "header" isn't a real one.
  - **The secure-origin half of both prefix contracts was
    unimplemented** -- browsers also require `__Secure-`/`__Host-` to be
    *set from* a secure origin, not just carry the `Secure` attribute
    (Chrome's `IsCookiePrefixValid` checks `SchemeIsCryptographic`), so
    e.g. `__Secure-sid` set over plain HTTP with `Secure` present was
    silently missed -- exactly the defect class this feature exists to
    catch. Both engines now also check this (loopback/localhost exempt,
    matching real browser behavior for local development).
  - **A prefix-violated cookie no longer also gets per-attribute
    findings** (`insecure-cookie`, `cookie-not-httponly`, `cookie-path-
    broad`, ...) describing a cookie that, per the violation finding
    itself, the browser never actually stored -- self-contradictory in
    a report, and inflated the executive risk score with 3-4x the real
    number of distinct issues for one root cause.
  - **A compliant `__Host-` cookie no longer also gets the pre-existing
    `cookie-path-broad` suggestion** -- `Path=/` is mandatory for
    `__Host-`, not a broad-scope hardening problem, so the two findings
    were telling the client to both set and narrow away from `Path=/`
    on the same cookie.
  - **`history.py`'s duplicate-(id,url)-key handling was
    order-dependent and its justifying comment was false** -- cookie
    findings (among others) routinely share a page's URL across
    multiple Set-Cookie headers, so a last-write-wins reduction made
    `--gate-on-severity-increase`'s verdict depend on list order within
    a JSON file. Duplicates now collapse by worst (most severe)
    severity, which is both deterministic and the conservative choice.
    A finding missing a `severity` key entirely is now also treated as
    unrecognized (previously defaulted to "info", which could still
    fabricate an increase).
  - **`trend` now takes `--suppressions`**, filtering both scans before
    diffing -- every other gate-capable command already honored
    suppressions; a formally-accepted finding could still fail
    `--gate-on-severity-increase` before this.
- **Fixed a self-caught false-positive source in
  `trend --gate-on-severity-increase`** ahead of review: an
  unrecognized severity string in the OLDER scan (a corrupted/hand-
  edited history file, or a future severity level the rank table
  doesn't know yet) defaulted to rank 4 ("as if info"), which meant ANY
  real severity in the newer scan -- even "low", the least severe real
  value -- would numerically look like an increase. The comparison now
  skips a key entirely when either side's severity string isn't one of
  the 5 known values, rather than guessing.
- **`shroodler trend --gate-on-severity-increase`** (Python-only;
  `shroodler-go` has no `trend` command at all yet, so this doesn't
  introduce a new gap). Catches a same-key finding (same id+url, so not
  "introduced") whose severity got worse between two scans -- something
  `diff --gate` structurally cannot see, since its static baseline
  (`expected_findings.json`) never records a severity to compare
  against, only presence. Rather than changing that on-disk baseline
  schema (which would have broken every existing committed baseline
  fixture and several exact-equality tests), this compares two full
  scan documents instead -- both already carry severity per finding, so
  no schema change was needed anywhere. Exits 1 when set and any
  same-key severity regression is found; `trend`'s JSON/text output
  also gained a `severity_increased` list either way.
- **New `__Secure-`/`__Host-` cookie-prefix violation checks, in both
  engines** (`packages/crawler-py/shroodler/extractors/cookies.py`,
  `packages/crawler-go/internal/extractors/cookies.go`). Distinct from
  the existing `cookie-missing-*-prefix` suggestions (adopt a prefix
  that isn't there): this catches a Set-Cookie whose name already
  carries the prefix but doesn't meet its contract (RFC 6265bis
  s4.1.3) -- `__Secure-` without `Secure`, or `__Host-` without
  `Secure`, with a `Domain`, or without an explicit `Path=/` (an
  omitted `Path` is itself a violation, the prefix requires it
  explicitly). Browsers reject such a Set-Cookie outright, so the
  application silently never has the cookie it thinks it set. Fully
  deterministic from the header alone, and applies regardless of
  whether the name matches this tool's own session-cookie heuristic.
- **Fixes from a pentester review of the executive-summary risk score --
  the two real ones were both genuinely misleading, not stylistic.**
  - **A single critical finding could grade the same "B" as a pile of
    unrelated mediums/lows.** `jwt-weak-secret` (full auth bypass: forge
    any user's token) scored 20 points, same band as e.g. 5 low-severity
    notes -- both landed on the same blue "B" badge. The grade is now
    floored by the single worst severity present (critical -> at worst
    F, high -> at worst D, medium -> at worst C), so volume of minor
    findings can never outrank the presence of one severe one.
  - **An unrecognized severity string was silently invisible.** A typo,
    a hand-edited findings file, or a future new severity level created
    an extra key in `severity_counts` that the template never reads --
    a report could show "4 findings" directly above "0 critical, 0
    high, 0 medium, 0 low, 0 info". Unrecognized severities are now
    bucketed into "medium" (counted, and still trips the severity
    floor) instead of vanishing.
  - **Added a `partial_coverage` flag and caveat** for when the scan
    itself reports it couldn't fully test the target (a WAF challenge,
    a skipped probe, a truncated redirect chain) -- a clean grade on a
    scan that was blocked out of half its checks was the most expensive
    possible misread this feature could cause, and the original version
    never said so.
  - **Reworded away from "Score N/100"**, which reads on a universal
    "higher is better" convention exactly backwards from what the grade
    means -- now "Grade: X (N risk points)".
  - Test suite now pins exact grades (not membership checks like
    `grade in {"C","D","F"}`) and adds the boundary cases the fixes
    above required: a single critical, an unrecognized severity string,
    and the partial-coverage flag.
- **Executive-summary risk score (0-100, A-F) in HTML and Markdown
  reports** (`packages/report-generator/risk_score.py`). Weighted by
  DISTINCT finding id per severity (critical=20, high=10, medium=4,
  low=1, info=0, capped at 100) using the same per-id grouping the
  technical summary table already computes -- deliberately not raw
  per-finding-instance count, so a single missing-CSP header repeated
  across 500 crawled pages scores as the one real issue it is, not 500,
  which would otherwise dwarf a scan that found five genuinely distinct
  critical vulnerabilities on one page. The HTML report gets a grade
  badge plus severity counts; Markdown gets a one-line summary. Pure
  presentation over data every format already had -- no new finding
  logic, so no correctness/false-positive surface to speak of.
- **`shroodler tokens` substantially reworked after a deeper pentester
  review found the entropy check false-positived on almost every
  correctly-implemented numeric OTP system, among other issues.**
  - **Per-string Shannon entropy replaced with a pooled length x
    observed-alphabet keyspace estimate.** A short string's entropy is
    bounded above by log2(its own length), so a 6-char token's ceiling
    (~2.6 bits/char) sat barely above the old 2.5 bits/char threshold --
    measured at ~98-99.7% false-positive rate against genuinely random
    6-digit OTPs across 20k trials. The new estimate (`min(len) *
    log2(|alphabet actually observed|)`, flagged below 64 bits as
    `reset-token-small-keyspace`, not `-low-entropy`) correctly reports
    a small OTP keyspace as a rate-limiting concern rather than
    misdiagnosing the RNG.
  - **Sequential detection switched from an absolute to a relative span**
    (`(max-min)/mean`), and now requires 3+ distinct values. The old
    absolute window (`span <= max(N*1000, 1000)`) missed a shared/
    tenant-wide auto-increment counter that jumps by hundreds of
    thousands between resets, and missed a millisecond-epoch token
    entirely -- both have a relative span many orders of magnitude
    below a random sample's regardless of absolute magnitude, so the
    relative check catches both while still correctly rejecting random
    OTPs. Values are validated with a strict `^[0-9]+$` check before
    being treated as integers (the bare `int()` call previously accepted
    PEP-515 underscores, leading `+`, and Unicode digit code points as
    "clean sequential integers").
  - **A structured/prefixed token (`"reset-" + timestamp`) no longer
    defeats both checks at once.** High per-string entropy from the
    varying digits previously hid a trivially-predictable timestamp
    behind a constant textual prefix. Non-digit characters are now
    stripped from each value before the sequential check runs (a
    per-value strip, not a cross-sample common-affix strip -- close-in-
    time epoch timestamps share several of their own leading digits too,
    and an early attempt at cross-sample stripping ate into that shared
    digit run and left too little behind to analyze).
  - **The id-shaped path-segment regex no longer merges unrelated
    endpoints.** It previously matched any 8+-char alphanumeric segment,
    including plain path words like "passwordreset"/"verifyemail" --
    merging two different flows with different generators into one
    (falsely) sequential-looking group, with the finding's evidence and
    URL attributed to the wrong endpoint. It now requires actual id
    shape (UUID, hex, all-digit, or a genuine digit+letter mix) and
    never matches pure-alphabetic text.
  - **Coverage widened**: the curated param list now includes Devise's
    `reset_password_token`, WordPress's `key`, and the near-universal
    `code`/`t`, among others; path-segment tokens (Django's
    `/reset/<uidb64>/<token>/`, Laravel's `/password/reset/{token}`) are
    now also detected on paths whose wording suggests a reset/
    verification flow.
  - **A new always-fired, always-true finding, `reset-token-in-url`**
    (medium): the token sitting in a URL leaks via Referer headers,
    proxy/CDN/server logs, and browser history regardless of how
    predictable it is -- the one thing this tool can state with full
    confidence from a single sample, which the original version never
    actually said.
  - **`reset-token-sequential` demoted from `critical` to `high`**,
    consistent with how every other single-session/small-sample signal
    in this codebase is scored (see `idor-adjacent-id-accessible`) --
    it's a strong statistical lead from a handful of samples, not a
    proven finding.
  - **Evidence no longer includes raw live token values.** Sample values
    in a finding's evidence are now redacted (first/last 2 characters
    only) before being written into a report -- the original version put
    up to 10 real, possibly still-valid tokens straight into the
    deliverable.
- **Three self-caught fixes to `shroodler tokens` ahead of review.**
  (1) Identical values observed more than once (a proxy recording
  naturally captures retries/redirect chains, or a tester revisiting the
  same emailed link) were counted as separate "samples" -- 3 identical
  observations of one real token would trivially satisfy the "2+
  samples" threshold and, worse, always look "sequential" (an identical
  value repeated has span 0). Values are now deduplicated before any
  multi-sample check runs, falling back to the single-sample estimate
  when only one distinct value remains. (2) The curated param-name list
  only matched underscore-style names (`reset_token`); a hyphenated
  `reset-token` (equally common in real APIs) silently fell outside it
  entirely. Param names are now normalized (hyphens to underscores)
  before matching. (3) Grouping was keyed on the literal path, so a
  common real API shape -- a per-request id segment alongside the token
  query param, e.g. `/reset/<uuid>/confirm?token=...` -- put every
  observation in its own singleton group, permanently preventing the
  multi-sample checks from ever running for that endpoint no matter how
  many samples were captured. A UUID/long-id path segment is now
  templated to a placeholder before grouping.
- **New `shroodler tokens` command: password-reset/verification-token
  predictability analysis** (`packages/crawler-py/shroodler/
  token_entropy.py`). Operates on a recorded proxy session (the same
  JSONL `--cookies-from`/`--seed-from`/`ingest-sessions` already
  consume), not a live crawl -- a reset token is normally delivered
  out-of-band (email/SMS), so the only way to observe one is a tester's
  browser, routed through the recording proxy, actually visiting the
  reset/verification link. With 2+ captured samples of the same
  parameter, tests whether the values are small/clustered integers
  (`reset-token-sequential`, critical) or measures real Shannon entropy
  across the sample set (`reset-token-low-entropy`, medium); with only
  one sample, makes a single conservative length-based estimate
  (`reset-token-short`, low) and says explicitly that it couldn't check
  for a sequential/low-entropy pattern with just one data point, rather
  than implying the same confidence as the multi-sample checks. A
  curated parameter-name list (token, reset_token, otp, ...) keeps this
  from firing on unrelated opaque query values (session IDs, CSRF
  tokens, API keys) that have entirely different generation/rotation
  properties than a one-shot emailed token. Python-only: this is a
  standalone command that never touches `crawl`, so there's no parity
  surface to port to Go at all.
- **Fixes from a second, deeper pentester review of the OAuth checks --
  four real issues, one of them a coverage gap serious enough to
  matter on almost every real engagement.**
  - **The check only ever ran on fetched, same-origin URLs.** In the
    dominant real-world architecture the relying party links or
    redirects to a *third-party* IdP (accounts.google.com, an
    Okta/Auth0 tenant, ...) -- off-origin, so the crawler's same-origin
    policy never fetches it, and the check (purely passive, needing no
    request) silently examined zero real authorization requests. It now
    also runs over every discovered link *before* the same-origin
    filter drops it, in both engines, with a new crawler-level
    integration test in each confirming the off-origin URL is flagged
    without ever being queued/fetched as a page.
  - **The self-fix from the first pass closed blank-value parity but not
    parser-leniency parity.** Go's `url.Query()` silently drops a pair
    whose value contains a bare `;` or an invalid `%`-escape, discarding
    the parse error, while Python's `parse_qs` keeps the literal text --
    for `state=a;b` that made Go treat `state` as *absent* (fabricating
    `oauth-missing-state` against a URL that does carry a state value)
    while Python correctly saw `"a;b"`. Both engines now refuse to
    assess a query containing either red flag at all, rather than
    reasoning from a partially-parsed result -- verified byte-identical
    against each other over an adversarial corpus (malformed escapes,
    semicolons, JAR/PAR, whitespace-only values) built during review.
  - **`packages/parity-tests/run_parity.py` discarded the query string
    entirely** when keying findings for comparison -- for a
    query-string-driven check like this one, that's the only place the
    signal lives, so two `/authorize` requests differing only by query
    could collapse into the same key and hide a real divergence. The
    finding key now includes the query string; verified by adding a
    real (intentionally state-less) `/oauth/authorize` link to the
    app4-microservices fixture (separate submodule commit) so this
    actually gets exercised end-to-end during a live parity run, not
    just asserted in a unit test.
  - **RFC 9101 (JAR) / RFC 9126 (PAR) requests were flagged
    `oauth-missing-state` even though they're a *more* secure deployment
    shape**, not less: `response_type`/`client_id` stay in the query for
    OAuth2 compatibility, but the real parameters (state included) live
    inside a signed request object or server-side, referenced only by
    `request`/`request_uri` -- state genuinely can't be assessed
    passively there. Both engines now skip the check entirely when
    either param is present.
  - Also: `oauth-implicit-flow` severity raised from `low` to `medium`
    (a token in the URL fragment is exploitable via history/referrer/
    redirector-log leakage and turns any open redirect on the relying
    party into a token-theft primitive; OAuth 2.1 removes this flow
    outright) and its evidence now includes the finding's URL, not just
    the decoded `response_type` value, so a report reader can locate it;
    `code_challenge` is now whitespace-trimmed the same way `state` is,
    closing a one-sided leniency where a whitespace-only PKCE challenge
    earned the full severity downgrade.
- **Two more OAuth check refinements, found on a second pass.** (1)
  `oauth-missing-state`'s PKCE downgrade now requires
  `code_challenge_method=S256` specifically, not just any
  `code_challenge` value -- RFC 7636's "plain" method (the default when
  the method param is omitted) sends the verifier itself as the
  challenge and doesn't hide anything in transit/logs the way S256 does,
  so it doesn't earn the same downgrade. (2) `oauth-implicit-flow` now
  checks whether `"token"` appears as one of the space-separated members
  of `response_type` (`strings.Fields`/`.split()`), not exact string
  equality -- OIDC's hybrid flow (`response_type=code token`,
  `code id_token token`, ...) still returns an access token in the
  redirect fragment, and exact equality against the whole value only
  ever caught the pure implicit-flow case, missing every hybrid variant.
  Both fixes landed identically in `extractors/oauth.py` and
  `extractors/oauth.go`.
- **Fixes to the OAuth checks' Python/Go parity, found while re-verifying
  round 4 by hand.** Python's `parse_qs` (default `keep_blank_values=False`)
  silently drops a blank occurrence of a repeated query param --
  `?state=&state=real` became just `{"state": ["real"]}`, hiding the
  blank first value entirely -- while Go's `net/url.Values.Get` returns
  the first value in the raw list (`""`) regardless. The two engines
  would have disagreed on whether `oauth-missing-state` fires for that
  URL. Python now parses with `keep_blank_values=True` and does its own
  explicit non-empty check, matching Go's semantics exactly (first
  occurrence decides, blank or not). Separately, Go's authorization-request
  detection used `q.Has("client_id")` (presence only) while Python
  required a non-empty value -- `?client_id=&response_type=code` was an
  authorization request to Go but not to Python; Go now also requires
  `q.Get("client_id") != ""`. Also added PKCE-awareness to
  `oauth-missing-state` in both engines: `code_challenge` present
  downgrades the finding to `low` (PKCE is widely considered adequate
  CSRF mitigation on its own in modern implementations) instead of
  treating every state-less request as the same risk as no CSRF
  protection at all.
- **New OAuth 2.0/OIDC authorization-request checks, in both engines.**
  `packages/crawler-py/shroodler/extractors/oauth.py` /
  `packages/crawler-go/internal/extractors/oauth.go`: purely passive
  (inspects a crawled URL's own query string, no extra requests). An
  "authorization request" is identified per RFC 6749 s4.1.1 by the
  presence of both `response_type` and `client_id` -- the two
  spec-required parameters for that request type, so there's no
  false-positive risk in deciding whether a URL even is one. Flags a
  missing/empty `state` param (`oauth-missing-state`, medium -- CSRF risk
  on the redirect callback) and `response_type=token`
  (`oauth-implicit-flow`, low -- the deprecated implicit flow, which
  exposes the access token in the URL fragment). Implemented in both
  engines rather than excluded from `run_parity.py`'s comparison, since
  it's simple enough (pure query-string parsing, no TLS/crypto library
  needed) to keep behaviorally identical instead of adding another
  Python-only category.
- **Fixes from pentester review of `--check-idor`.** A same-shaped JSON
  object under the same session cannot, by itself, distinguish a real
  IDOR from the requesting session's own neighboring record (sequential
  IDs are frequently allocated in a batch to one account) -- the finding
  is now `medium` severity (was `high`) with a description that says so
  explicitly and asks for manual ownership confirmation, rather than
  reading as a proven vulnerability. Also fixed a real bug: candidate
  dedup was keyed on the whole URL, so a URL with more than one numeric
  position (e.g. `/users/5/orders/123`, or `?account=1&order=456`) kept
  only the first one found and silently dropped the rest, fuzzing the
  wrong parameter; now keyed per numeric position. Query candidates also
  skip a denylist of common non-ID numeric params (`page`, `limit`,
  `year`, ...) that would otherwise generate reliable false positives
  (every page of a paginated list has the same JSON shape). Zero-padded
  IDs (`/orders/007`) now preserve their width when building adjacent
  candidates instead of silently renormalizing to `/orders/6`, which
  could 404 a legacy zero-padded route for a formatting reason unrelated
  to authorization. The fixed not-found-baseline offset's real limitation
  (weakest on huge/Snowflake-style ID spaces, where `id + offset` may
  itself be a valid, differently-owned object) is now documented in the
  module rather than silently assumed away.
- **`--check-idor` (Python-only, off by default): same-session
  ID-sequence probing.** For a crawled URL with a purely-numeric path
  segment or query value, replays adjacent IDs (n-1, n+1) using the
  crawl's own session (`packages/crawler-py/shroodler/extractors/
  idor.py`) and flags one that returns a genuine 2xx with the same
  top-level JSON key shape as the original -- distinct from the existing
  `authz-diff` (which replays a *higher-privileged* crawl's URLs under a
  *lower-privileged* session; this is same-privilege, adjacent-object
  access). Scoped deliberately narrowly to avoid the false-positive traps
  earlier reviews caught: JSON API responses only (HTML/other content
  types are skipped rather than guessed at via fuzzy body-length
  heuristics), and a synthetic not-found-shaped ID is probed first as a
  baseline -- if the target doesn't distinguish valid from invalid IDs by
  status/shape at all (e.g. it returns 200 for everything), the check
  can't prove anything and skips rather than reporting a finding neither
  status code nor response shape actually supports. Off by default (like
  `--check-rate-limit`) because it makes real extra GET requests for IDs
  that were never organically discovered, which could read another
  user's data on a genuinely vulnerable target -- an authorized-testing
  judgment call, not a parity concern this time.
- **TLS checks: real chain-trust validation, handshake-failure signal, and
  an IP-SAN false-positive fix.** A pentester review of the TLS checks
  found the disabled-verification design meant an untrusted-CA/broken
  chain cert (issuer != subject, so not "self-signed", but still nothing
  a normal client would trust) reported clean; `check_tls` now also
  attempts one real, verified handshake (system trust store) and emits
  `tls-untrusted-chain` when that fails for a reason none of the other,
  more specific checks already explain (skipped when the cert is already
  known expired/self-signed/hostname-mismatched, so this never fires a
  second, less-specific finding for the same cert). A TLS handshake that
  fails after the TCP connection succeeds (e.g. a protocol/cipher the
  client refuses) now also gets a low-severity `tls-handshake-failed`
  lead instead of being silently collapsed into "not applicable" the same
  way a boring connection-refused is. Also fixed, and this one really
  matters given Shroodler's own default posture of scanning
  127.0.0.1/localhost: `hostname_matches()` only ever checked `x509.DNSName`
  SAN entries, so a certificate correctly issued for an IP address (which
  RFC 6125 requires as an `iPAddress` SAN, never a DNS name or the CN)
  was always misreported as `tls-hostname-mismatch` -- a real false
  positive against exactly the target shape this tool scans by default.
- **`packages/parity-tests/run_parity.py` now fails loudly if
  shroodler-go starts emitting a category on `PYTHON_ONLY_CATEGORIES`.**
  That exclusion list is how the always-on `subresource`/`tls` checks
  avoid being compared against an engine that doesn't implement them yet;
  without this guard, the exclusion would keep silently hiding a real
  Python/Go divergence forever if Go ever gained one of those categories
  without this list being updated.
- **TLS certificate checks** (`packages/crawler-py/shroodler/extractors/
  tls.py`, new `tls` finding category, Python-only for now). Runs once per
  crawl against an `https://` target's origin, independent of the crawl's
  own httpx client (which already refuses to connect at all over a truly
  broken cert, since it verifies by default) -- opens its own
  verification-disabled connection specifically to report on *why* a cert
  is broken: expired, expiring within 30 days, self-signed (issuer equals
  subject), or hostname mismatch (checked against SAN, falling back to CN
  only when no SAN exists, per RFC 6125). Uses the `cryptography` library
  (new dependency) to parse the certificate deterministically rather than
  classifying by matching OpenSSL/Python's own verification-error
  *message* text, which is not stable across OpenSSL/Python versions --
  exactly the kind of fragile proxy-for-truth the command-injection fix
  above was about. Excluded from `packages/parity-tests/run_parity.py`'s
  comparison the same way the `subresource` category is.
- **New `lfi.yaml` payload pack**: PHP stream-wrapper-based local/remote
  file inclusion, distinct from the existing plain path-traversal pack
  because it targets an `include()`/`require()` sink rather than a
  file-read sink. `php://filter/read=string.rot13/resource=/etc/passwd`
  proves inclusion happened via a rot13'd match signature ("ebbg:k:0:0")
  that cannot appear from the target merely reflecting the raw payload
  text back (same discipline as the command-injection arithmetic markers
  above); `data://` with a base64 payload that computes `7*13` at runtime
  proves full RCE the same way, when `allow_url_include` is enabled.
- **New active-payload packs: OS command injection and CRLF/HTTP header
  injection.** Pure YAML additions (`packs/command-injection.yaml`,
  `packs/crlf-injection.yaml`) consumed by both engines' existing generic
  pack loader/matcher. Command injection uses shell arithmetic markers
  (`$((87340006+1))` -> `87340007`) so a match can only come from actual
  execution, not from an endpoint that merely echoes its input back (an
  earlier version of this pack matched on the payload's own literal text,
  which is exactly what ordinary reflection also does -- fixed after
  review, along with the app5-injectable test fixture that had
  accidentally "proven" the broken version via reflection rather than
  execution); a separate, lower-confidence blind/timing variant uses the
  pack engine's `time_delta_gte_ms` matcher (`medium` severity, since a
  single unconfirmed timing sample can false-positive on ordinary
  network/GC jitter). CRLF adds a new shared match-clause type,
  `header_contains` (ported to both the Python and Go payload engines,
  with tests on both sides), which scans every response header's value
  rather than only `Location` -- a real response-split lands the injected
  text wherever the HTTP client's own parser splits it out (often an
  extra header/cookie line), which `redirected_to_contains` alone cannot
  see.
- **Subresource Integrity and mixed-content checks, always on in
  crawler-py.** Flags cross-origin `<script>`/`<link rel=stylesheet>`
  tags without an `integrity=` attribute, and HTTPS pages loading
  `http://` subresources. `shroodler-go` doesn't implement this yet, so
  rather than hide it behind an opt-in flag nobody would think to enable
  (the initial version of this change did exactly that, to protect
  `packages/parity-tests/run_parity.py`'s Python/Go comparison), the
  "subresource" finding category is instead excluded from that
  comparison directly -- the check runs by default like every other
  passive extractor, and the parity gate stays honest about which
  category is Python-only instead of the feature being invisible.
- **Reports now carry remediation guidance per finding**
  (`packages/report-generator/remediation.py`). HTML and Markdown output
  gets a one-line fix suggestion per finding id, with a category-level
  fallback so newly-added payload/secret pack ids aren't silently blank
  until someone remembers to update the table.
- **Redirect-chain truncation actually works now (Python + Go).** The
  per-URL redirect counter (`max_redirects`) was dead code in Python: a
  URL's canonical key is added to `seen` before it's ever fetched, so the
  queue can only process each key once, meaning the counter could never
  exceed 1 regardless of `max_redirects` -- only the global `seen` set
  (catching an exact A->B->A loop) plus the outer page/time budget
  (eventually running out) ever actually stopped a chain, silently
  eating page-budget slots one hop at a time with no visibility. Go had
  no protection at all beyond `seen`+budget. Both engines now track
  chain depth forward across distinct canonical keys and emit a
  `redirect-chain-truncated` scan-note finding when a chain exceeds
  `--max-redirects` hops, so a report reader can tell "this site's
  redirect design ate N budget slots" from a real content gap.
- **`js-endpoint` extraction covers more real-world API-client call
  shapes** (Python + Go): `axios.get/post/put/patch/delete/head/options(...)`
  (previously only the bare `axios(...)` form matched, but real SPAs
  overwhelmingly call axios per-method), jQuery's `$.get/$.post/$.getJSON`
  and `$.ajax({url: ...})`, and raw `XMLHttpRequest`'s `.open(method, url)`.
  Go was also missing the pre-existing `axios(...)`/`request(...)` pattern
  entirely -- a real, previously-unnoticed parity gap, now fixed in the
  same change.
- **`parity-tests` now compares finding severity, not just id+path.** A
  regression that flipped a finding's severity between the two engines
  (e.g. a real vulnerability silently downgraded to `info`) would
  previously report "parity ok" as long as the (id, path) pair still
  matched -- this is wired live into CI via `make verify`, so it was an
  active, not theoretical, gap.
- **`payload` now fuzzes GET endpoints with no `<form>` using `Page.params`.**
  Both crawlers have populated `Page.params` (query-parameter names) for
  every page for a while -- via OpenAPI/GraphQL discovery and plain
  query-string parsing -- but `payload-tester` only ever iterated
  `page.forms`, so a bare `GET /search?q=...` with no surrounding HTML
  form (the common shape for API-style targets) got zero fuzzing even
  though its real parameter names were already sitting in the crawl
  JSON. The tester now also treats each page's own URL as a synthetic
  GET-only "form" when `params` is non-empty, reusing the exact same
  baseline/pack-matching/dedup path as a real form. Fixed in the same
  change: a page whose own URL carries a query string *and* has a real
  `<form>` extracted from its HTML targeting the same underlying path
  (query string aside) would otherwise get every payload sent twice --
  the synthetic target is now skipped when an existing form already
  covers that path, so request volume/side effects don't double for
  zero extra coverage.
- **Fixed real bugs in the Go authz-diff/session-checks port** found by a
  pentester critique of the initial port: (1) session-cookie lookup used
  `jar.Cookies(seedURL)`, which applies Go's cookiejar domain/path
  matching -- a cookie scoped narrower than the seed URL (or set by a
  different endpoint) was silently invisible to both checks, unlike
  Python's unscoped `client.cookies`. Replaced with a response-wide
  cookie recorder (a thin RoundTripper) that matches Python's actual
  semantics. (2) The login submission didn't follow redirects, unlike
  Python's explicit `follow_redirects=True` override for that one
  request -- a login flow with an SSO/interstitial hop before the
  cookie-rotating response would falsely trigger `session-fixation`.
  Fixed by giving just the submit request its own redirect-following
  policy. (3) A malformed `logout_url`/`protected_url` (wrong JSON type)
  aborted the whole crawl instead of just disabling the affected check,
  unlike Python's always-succeeds coercion -- now decoded leniently. (4)
  `resolveOne` used naive origin-rooted path replacement instead of real
  relative-URL resolution, so a non-rooted relative `logout_url`/
  `protected_url` (e.g. `"logout"` under `/account/login`) could resolve
  to the wrong path -- now uses proper RFC 3986 resolution.
- **Go parity: `authz-diff`, session-fixation, logout-invalidation.** These
  were Python-only since 0.2.0. `shroodler-go` now has a full `authz-diff`
  subcommand (same flags/output shape as Python: `--cookie`, `--header`,
  `--no-anon-check`, `--allow-external`, `--output`), and `--login-recipe`
  crawls in `--mode static` now run the same session-fixation and
  logout-invalidation checks Python has -- a `LoginRecipe`'s `logout_url`/
  `protected_url` fields are honored, and `--mode headless` emits the same
  `session-checks-skipped-headless` scan-note Python does rather than
  silently skipping. Ported edge-case-for-edge-case against the existing
  Python test suite, including the previously-fixed "ordinary redirect
  isn't a denial" behavior in `authz-diff`'s anonymous-control check.
- **Challenge-cookie signature tier + single-retry recovery** (Python + Go):
  known challenge-issuance cookies (`cf_clearance`, `__cf_bm`, `incap_ses_*`,
  `ak_bmsc`, `_abck`, DataDome, etc.) are now a detection signal too (gated
  on a 403/503 status, same tier as the existing "weak" body/header
  signatures). When a challenge response sets one of these cookies, the
  crawler now retries that single URL exactly once through the same cookie
  jar before finalizing the finding -- these cookies are typically issued
  *on* the challenge response itself, so a transient challenge often
  clears on the very next request. Still detection-only: this never
  solves or bypasses anything, it just avoids treating a one-off hiccup
  as a durable block. The `waf-challenge` finding's `evidence` field now
  carries the matched vendor name.
- **Site-wide challenge escalation**: a single challenged page and a
  target that's WAF-fronted across most of the site used to look
  identical in the output (same category, no distinguishing signal). A
  new `waf-challenge-sitewide` (high-severity) finding fires when at
  least 3 pages and at least 30% of the crawl were challenged, naming the
  vendor(s) involved, so a report reader can tell "ignore this one URL"
  from "this scan's other findings substantially understate the target's
  real surface."
- **Docs**: the `--check-rate-limit` man page entry now cross-references
  `waf-challenge`/`--user-agent`, since repeated rate-limit-probe requests
  can themselves trip a WAF mid-scan.
- **WAF/bot-mitigation challenge detection** (Python + Go): the crawler now
  recognizes Cloudflare/Akamai/PerimeterX/DataDome/CAPTCHA challenge and
  interstitial pages instead of silently crawling them as real content --
  a page that trips a challenge signature gets a high-severity
  `waf-challenge` finding and is excluded from form/secret/JS-endpoint/
  verbose-error/markup extraction (header/cookie extraction still runs,
  since those describe the real HTTP exchange). Detection only: Shroodler
  never attempts to solve or bypass a challenge. New `waf-challenge`
  finding category (schema bump).
- **`--user-agent`** on `shroodler crawl` (Python + Go): the User-Agent was
  previously unconfigurable from the CLI in both engines (Go didn't even
  thread it through as a parameter -- every request hardcoded the literal
  `Shroodler/0.1.0` string). Some targets serve different content, or block
  requests outright, based on User-Agent.
- **Soft-404 baseline for common-path/backup-mutation probing** (Python +
  Go): apps that return HTTP 200 with a branded/templated "not found" page
  for any unknown path were flooding `probe_paths`/`probe_mutations` with
  false-positive `exposed-file` hits. The crawler now fingerprints one
  known-nonexistent path per scan and suppresses wordlist hits that match
  its status/body.
- **Fixed a budget-bypass bug** in the Python crawler: `probe_mutations`
  (backup-suffix mutation probing) ignored `--max-pages`/`--max-time`
  entirely, unlike `probe_paths` which already respected both -- a crawl
  could run well past its configured budget during this phase. Go was not
  affected (its mutation loop already checked the budget per-request).
- **`--oob-host`** on `shroodler payload`: point `{{MARKER_HOST}}` at your
  own collaborator-style server (self-hosted Interactsh, an `oast.*`
  instance, or any host you control that logs requests) instead of the
  non-resolving default placeholder. New `blind: true` pack flag for
  checks Shroodler cannot verify itself (parameter-entity XXE, OOB SSRF) --
  it sends the payload and records the token/URL/pack in the output's
  `oob_probes` list for you to correlate against your own server's logs
  afterward. Python + Go parity.
- **Fixed a real, previously-silent bug** in open-redirect detection: the
  payload tester followed redirects by default, which meant it tried to
  actually connect to the (often non-existent or attacker-controlled)
  redirect target to chase the chain. When that target didn't
  resolve/respond -- including the tool's own default marker host, which
  lives under the reserved `.invalid` TLD and can never resolve -- the
  connection error was silently swallowed, skipping the check entirely.
  Payload requests no longer follow redirects; the Location header is read
  directly from the single response instead. Python + Go.
- Post-review bug fixes from a harsh re-review of the feature-expansion
  round below: `authz-diff` no longer treats a bare 3xx redirect as
  "denied" (was manufacturing false positives on ordinary redirects);
  `--profile` now wins over `~/.shroodlerrc`; added `--no-check-rate-limit`
  to force that flag off even under `--profile aggressive`; the JWT audit
  no longer embeds the actual cracked secret in report output (Python +
  Go); session-fixation/logout checks emit a `scan-note` when skipped in
  `--mode headless` instead of silently no-op'ing; tightened the
  Windows-hosts XXE signature.

## 0.2.0 -- Post-review hardening + CLI feature expansion

New detection and workflow capabilities, on top of the hardening pass
below (both landed under this version -- neither was ever tagged/published
separately):

- **XXE payload pack** (`packages/payload-tester/packs/xxe.yaml`): local-file-read
  detection for raw-XML-body endpoints (SOAP/XML-RPC/etc.), plus a
  parameter-entity OOB-marker payload documented as undetectable without a
  real collaborator listener.
- **JWT static-analysis audit** (Python + Go): decodes any JWT-shaped token
  found in a response and flags `alg:none`, missing/unusually long `exp`,
  and weak HMAC secrets cracked against a small built-in wordlist.
- **`--check-rate-limit`** (opt-in, off by default): fires repeated
  bad-credential requests at discovered login/auth-shaped forms and flags
  the endpoint if nothing in the response stream suggests throttling,
  lockout, or CAPTCHA. Python + Go parity.
- **`shroodler authz-diff`**: replays a privileged crawl's page URLs under a
  second, lower-privileged session; flags broken access control when a URL
  an anonymous request can't reach is still reachable with the wrong
  session (a lightweight IDOR/broken-access-control check).
- **Session-fixation and logout-invalidation checks**: when `--login-recipe`
  is used, the crawler now compares the session cookie before/after login
  (flags `session-fixation` if unchanged) and, if the recipe declares a
  `logout_url`, checks whether the pre-logout session cookie still works
  afterward (flags `logout-session-not-invalidated`).
- **`shroodler history` / `shroodler trend`**: a local scan-history store
  (default `~/.shroodler/history`) and a lightweight "what changed between
  these two scans" diff, distinct from `diff --gate`'s static-baseline CI
  gating.
- **`--profile {safe,balanced,aggressive}`** on `crawl`: bundles
  depth/max-pages/max-time/check-rate-limit into named starting points;
  any explicit flag on the command line still overrides the profile.
- New `auth` finding category (schema + Python `Category` enum) covering
  all of the above session/authorization findings.
- Packaging: PyPI-style metadata (classifiers, keywords, project URLs) on
  both `shroodler` and `shroodler-cli`; `shroodler-cli` now declares its
  dependency on `shroodler`.

Known gaps, intentionally out of scope for this round: no out-of-band
(collaborator-style) detection for blind SSRF/XXE/SSTI -- that needs a
reachable DNS/HTTP listener, which is a real infrastructure decision left
to the operator (see `docs/cli-surface.md`). `authz-diff` and the
session-fixation/logout checks are Python-only; `shroodler-go` does not
yet have parity for these two (CLI/session-flow orchestration, not core
crawler detection logic).

### Hardening fixes (same 0.2.0 release)

From a multi-round adversarial review of the CLI/payload surface, fixed
before the feature work above:

- `payload-tester` gained `--allow-external` (was hardcoded to refuse any
  non-local target), a per-form baseline request, and low-false-positive
  match primitives (`new_only`, `error_status_changed`, `time_delta_gte_ms`,
  `redirected_to_contains`).
- SQLi/XSS payload packs reworked to require real DB-error signatures (not
  bare status changes) for high severity, plus new time-based blind SQLi
  payloads and multi-context XSS payloads.
- New `ssrf.yaml` (cloud metadata) and `open-redirect.yaml` payload packs.
- Secret-pattern severity fixes: Stripe live/test keys split, generic JWT
  and Google API key severity downgraded with explanatory text to cut
  false positives.
- CORS/GraphQL active probes now honor `--allow-external` and emit an
  explicit `scan-note` finding instead of silently no-op'ing (Python + Go).
- `finding.schema.json` gained `schema_version` and now matches real
  Go/Python output (`payload`, `scan-note` categories).
- SARIF output now encodes `artifactLocation.uri` as a relative path
  (GitHub code-scanning compatible) instead of a raw live URL.
- `--debug` flag for full tracebacks; HTML report gained a grouped summary
  table so large crawls stay readable.
- Apache-2.0 `LICENSE` added; `docs/cli-surface.md` added, mapping every
  CLI capability to whether the desktop UI wires it up yet.

## 0.1.0 -- Initial toolkit

Dual Go/Python crawlers with parity tests, passive checks (headers, CORS,
cookies, secrets, GraphQL/OpenAPI discovery), a payload-pack-driven active
tester (SQLi/XSS/SSTI/path-traversal), an intercepting proxy, a Tauri
desktop shell, and CI-friendly baseline diffing/gating against five
intentionally vulnerable target apps.
