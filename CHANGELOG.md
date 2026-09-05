# Changelog

All notable changes to Shroodler are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project has
not yet made a versioned PyPI release, so entries below are grouped by the
work that produced them rather than tags.

## Unreleased

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
