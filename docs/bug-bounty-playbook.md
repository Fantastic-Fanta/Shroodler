# Bug bounty playbook

A practical, start-to-finish workflow for using Shroodler on a real Bugcrowd
(or similar) engagement, distilled from an actual session against a
Cloudflare + Castle.io–protected staging target. Read this before starting a
new engagement instead of re-deriving the setup from scratch.

## 1. Pick a program

- Prefer **Managed** programs (Bugcrowd's own triage team screens
  submissions first) over self-managed ones for your first attempts —
  faster, more consistent feedback.
- Prefer a **narrow, clearly-scoped** program over a broad `*.company.com`
  one. Check the Bugcrowd "Scope rating" (1-4 stars) on the engagement page
  — a 1/4 rating means little attack surface exists; calibrate your time
  expectations accordingly, and don't be surprised if a narrow-scope,
  well-engineered target yields nothing. That's a legitimate result, not a
  failure.
- Read the **Details** tab in full: Targets (in-scope/out-of-scope),
  Excluded Submission Types, Access/Credentials, Safe Harbor. The exclusion
  list tells you what *not* to waste time on (e.g. self-XSS unless
  UI-exploitable, missing-header-only reports, CSRF on unauthenticated
  pages, TLS issues unless severe, subdomain takeover if they say it's
  safeguarded).
- Complete Bugcrowd identity verification *before* you need to submit — it
  can get stuck ("Continue verification") for hours; this blocks payment on
  Managed programs (not on VDPs) but doesn't block testing.

## 2. Local environment

```bash
make bootstrap   # pulls the vulnerable-target-apps submodule (local testing only)
make install-cli # builds shroodler / shroodler-go / shroodler-proxy, symlinks to ~/.local/bin
```

If binaries aren't on `PATH`, use `.venv/bin/shroodler` and
`packages/proxy-go/shroodler-proxy` directly.

## 3. Passive pass first (always safe)

```bash
shroodler crawl https://target-marketing-site.example --allow-external \
  --depth 3 --profile safe --output pass1.json
```

Triage before reporting anything:
- **`secret` findings that repeat identically across every page** are
  almost always false positives (CDN/CMS asset hash IDs, e.g. Contentful
  image URLs), not real API keys. Check `evidence` values for a shared
  prefix/pattern before treating as real.
- **Missing-header / missing-SRI findings that show up hundreds of times**
  are one systemic issue, not N issues — and are frequently explicitly
  excluded by the program (check their Excluded Submission Types) or
  scored as low/non-qualifying by triagers on their own.

## 4. Authenticated testing: crawler vs. proxy

Try the crawler first — `--mode headless --cookie "name=value"` — but be
ready for it to fail against real production infra:

- **WAF/bot-management (Cloudflare, Castle.io, etc.) blocks automated
  clients outright**, even with a fully valid session cookie/token. Signs
  of this: `pages_challenged` far exceeds `pages_crawled` in the crawl
  output, or every request returns a Cloudflare "Attention Required" 403
  page. This isn't a bug in the target — it's their WAF doing its job. When
  you see it, **stop trying to make the automated crawler work** and
  switch to the proxy-and-record workflow below.
- Any endpoint gated by a **per-request, JS-SDK-issued anti-fraud token**
  (Castle.io's `X-Castle-Request-Token` is a common one) cannot be
  meaningfully replayed via curl/Shroodler at all, valid session or not.
  Testing that needs a real, JS-executing browser — plan for manual
  browser-driven testing on such targets, not raw HTTP replay.

### Proxy-and-record setup

```bash
packages/proxy-go/shroodler-proxy ca generate
packages/proxy-go/shroodler-proxy ca export --output ~/Desktop/shroodler-ca.pem
packages/proxy-go/shroodler-proxy start --port 8888 --control-port 8890 \
  --record /tmp/session.jsonl
```

1. **Trust the CA** (macOS): Keychain Access → File → Import Items → the
   exported `.pem` → find it under the **Certificates** tab (not "My
   Certificates" — it has no private key) → double-click → expand Trust →
   "Always Trust". If Finder/Keychain won't show `/tmp`, copy the file to
   `~/Desktop` first (`/tmp` is a hidden path in file pickers).
2. **Scope the browser proxy to the target only** — do not proxy all
   traffic. In FoxyProxy: set mode to "Proxy by Patterns" (not "use this
   proxy for all URLs"), add an Include/Wildcard pattern like
   `*target-domain.com*`. Verify the general macOS System Settings →
   Network → Proxies are **not** also enabled system-wide — a
   double-proxy (system-wide + extension) will route *unrelated* app/OS
   traffic through your recording, and you will capture live credentials
   for things that have nothing to do with the engagement (Slack, Spotify,
   your password manager, etc.). Delete any capture file that has this
   contamination immediately rather than trying to filter it after the
   fact.
3. Browse the target manually, authenticated, through the proxied browser.
4. `shroodler ingest-sessions` / `shroodler tokens` / `shroodler
   authz-diff` on the recorded JSONL afterward — this is passive analysis
   over already-captured traffic, so it never gets WAF-blocked.

## 5. Manual injection-testing checklist

Don't just "click around" — target these methodically, seeding payloads
you can trace, and use a shared multi-user surface so results are
cross-user (not self-XSS, which most programs explicitly exclude):

1. Basic tags/attributes in every free-text field (name, memo, notes):
   `<b>test</b>`, `<script>alert(1)</script>`, `{{7*7}}`, `${7*7}`.
2. If a WAF blocks obvious `alert(`/`onerror=`/`onload=` shapes, that's a
   403 from the edge, not a verdict on the app's own escaping — you have
   not tested the app yet. Either try less-signature-obvious payloads, or
   accept you can't cleanly separate "app escapes it" from "WAF ate it"
   without more sophisticated evasion (usually not worth the effort/risk
   for a manual test).
3. **Invite a second test account into a shared context** (shared
   budget/workspace/project) and re-check every payload from that
   account's view. Only *then* does a rendering failure count as real
   stored XSS rather than excluded self-XSS.
4. **Export/report paths are a separate code path** from the live UI and
   often escape differently — test CSV/PDF export separately:
   `=1+1`, `@SUM(1+1)`, `+cmd`, `-2+3` in exported fields (CSV/formula
   injection). Check the *raw* file content (not reopened in Excel/Numbers,
   which may auto-mitigate on open) — look for a backslash or other
   explicit escape prefix as evidence of a real mitigation.
5. **Authz-diff**: capture object IDs (transaction/account/category) from
   account #1, then — without ever sharing/inviting — try accessing them
   directly as account #2. This needs a *real browser* if the target has
   bot-detection gating raw API replay (see §4).
6. **Session lifecycle**: logout invalidation, session fixation. Note:
   *one device's logout not affecting another device's independent
   session is normal, expected multi-device behavior* in virtually every
   modern app — don't report this. What *would* be a finding: a stolen
   token/cookie captured before logout still authenticating requests
   *after* that same session logs out.
7. Missing rate limiting on login/2FA: deliberately fail a code 5-6 times
   back-to-back, note whether anything throttles you.

## 6. Calibrating findings before you submit

Get a second opinion (a different model, or re-derive from first
principles) before submitting anything non-obvious. In this session, a
"token discloses internal ID + bcrypt salt" writeup did not survive
scrutiny once someone pointed out that **bcrypt salts are not secret by
design** — the whole finding rested on treating non-secret-by-design data
as if it were a leak. Lessons:

- If the "impact" section of your own writeup is doing a lot of "this
  *could* enable X in combination with some other bug that doesn't
  currently exist," that's a strong signal it's not a real finding —
  almost any internal identifier can be argued into a hypothetical chain.
- Verify the actual cryptographic/security properties of what you found
  (is a salt supposed to be secret? is an HMAC-signed value supposed to be
  unreadable, or just untamperable?) rather than pattern-matching on
  "looks like credential material."
- A submission that gets closed as Not Applicable costs you signal score.
  Not submitting a shaky finding is better than submitting one.
- Conversely, don't be afraid to submit an honestly-scoped **Low**
  severity finding — a correctly-calibrated small finding builds triage
  trust for your next, bigger one.

## 7. Knowing when to stop

If you've hit all of: WAF blocking payload-shaped input, bot-detection
blocking raw replay, clean output-escaping, clean CSV-export escaping, and
standard/expected session behavior — that's a legitimately well-engineered
target, and further blind probing has low expected value. Move to a
different, less-hardened program rather than grinding. A Bugcrowd "Scope
rating" of 1/4 is itself an early warning sign of this outcome.
