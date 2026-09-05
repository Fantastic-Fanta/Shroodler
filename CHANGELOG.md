# Changelog

All notable changes to Shroodler are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project has
not yet made a versioned PyPI release, so entries below are grouped by the
work that produced them rather than tags.

## Unreleased

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
