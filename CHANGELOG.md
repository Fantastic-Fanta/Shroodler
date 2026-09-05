# Changelog

All notable changes to Shroodler are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project has
not yet made a versioned PyPI release, so entries below are grouped by the
work that produced them rather than tags.

## Unreleased

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
