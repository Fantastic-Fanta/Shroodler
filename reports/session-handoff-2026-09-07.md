# Bug bounty session handoff — 2026-09-07

Picking this up in a new session? Read this first, then check the
per-program notes files linked below for full detail.

## Setup reminders

- CLI: `export PATH="$HOME/.local/bin:$PATH"` then `shroodler`,
  `shroodler-go`, `shroodler-proxy` are on PATH. Rebuild anytime with
  `make install-cli` from the repo root.
- Standard UA used for all external scans this session (identifies the
  scan, links back to the relevant program):
  `Mozilla/5.0 (compatible; Shroodler-BugBounty/0.2; +<program-brief-url>)`
- **zsh gotcha hit twice this session**: never name a shell loop variable
  `path` -- zsh ties it to `$PATH` and silently breaks every command
  after the loop starts (`command not found: curl` etc, no obvious
  cause). Use `ep`, `h`, anything else.
- Long-running `shroodler payload` runs: always run via `nohup ... &`
  backgrounded and poll, never a plain foregrounded call with an
  arbitrary `timeout N` wrapper -- a killed-early run leaves no output
  file at all. Check request counts against a rough estimate (payloads
  x targets x ~1-3 requests each) before assuming a long runtime is a
  bug rather than just self-throttled politeness.

## Programs in play

### 1. Internet Brands Public (Bugcrowd, public program)
https://bugcrowd.com/engagements/internetbrands-public
Notes: `reports/internetbrands/notes.md`

- Most listed hosts turned out to be redirect aliases or SSO-gated
  (portalv2.lh360.com -> Keycloak, not pursued further -- no test
  account, user chose not to request one).
- **Submitted**: cookie security finding on `exchange.pulsepoint.com`
  (`CWAuthTkt_CROSS_DOM` and session cookies missing `Secure`, plus
  `HttpOnly` missing on the session id, broad `.pulsepoint.com` domain
  scope, no HSTS). Draft at `reports/internetbrands/pulsepoint-cookie-report.md`.
  VRT: Broken Auth/Session Mgmt > Cleartext Transmission of Session
  Token, Bugcrowd auto-classified this **P4**. Submitted by user via
  the browser form I filled in.
- Status: essentially wrapped up, low remaining upside on this program
  unless revisiting with more time.

### 2. PlanetHoster (Bugcrowd, public program)
https://bugcrowd.com/engagements/planethosterinc

- **Blocked on**: user requested test credentials (program provides a
  real account + EUR100 test credit on request, click "Get
  Credentials" at the bottom of the brief) -- had not arrived as of
  end of session. No exploration done yet.
- Why it's worth returning to: real test account + payment-flow
  testing + documented Domain/World REST APIs + explicit "Access to
  other users' accounts/information" focus area (i.e. they want
  IDOR/BAC testing) + higher reward ceiling (P1 $2000-3000) than the
  other programs here.
- **Next step once credentials arrive**: log in, explore
  world.planethoster.net panel + the two REST APIs
  (api.planethoster.net/{reseller-api,world-api}), focus on
  cross-account access (Shroodler's `authz-diff` command is built
  exactly for this: crawl as one account, replay as another with
  `--cookie`).

### 3. Cisco ThousandEyes Vulnerability Hunting (Bugcrowd, private program user has access to)
https://bugcrowd.com/engagements/thousandeyes-og

- **Blocked on**: user needs to self-register at
  https://www.thousandeyes.com/signup using a `@bugcrowdninja.com`
  email (program requires this exact email domain or submissions are
  rejected). Not done yet as of end of session.
- Important constraint if resumed: **this program explicitly forbids
  automated vulnerability scans / brute-force enumeration** and
  requires a custom User-Agent (`Bugcrowd-<username>` appended to
  every request). Do NOT run Shroodler's crawler/payload engine here
  the normal way -- lean on manual, single-purpose requests, the way
  the PulsePoint cookie finding and the Vienna CORS finding were both
  actually found (by hand, informed by passive recon, not by blasting
  payload packs).
- Scope once account exists: `app.thousandeyes.com` (SaaS dashboard),
  `www.thousandeyes.com` (marketing+signup), `api.thousandeyes.com`
  (customer API). Reward ceiling P1 $4100-4500 -- the biggest of any
  program touched this session.

### 4. City of Vienna Managed Bug Bounty (Bugcrowd, public program) -- most active
https://bugcrowd.com/engagements/city-of-vienna-mbb-og
Notes: `reports/vienna/notes.md` (full scope list, per-host detail)

No public disclosure allowed for this program -- keep everything to
Bugcrowd only, same as always but explicitly stated in this brief.

Self-serve account signup (no waiting) via `@bugcrowdninja.com` email
if deeper/authenticated testing is wanted -- not done yet.

**Submitted**: CORS misconfiguration on `digitales.wien.gv.at`'s
WordPress REST API -- every `/wp-json/` route reflects an arbitrary
`Origin` with `Access-Control-Allow-Credentials: true`. Confirmed via
curl (not just Shroodler's own flag) across `/wp-json/`,
`/wp-json/wp/v2/users`, oembed, and an OPTIONS preflight against
`wp/v2/users/me`. Draft at `reports/vienna/digitales-cors-report.md`.
VRT: Server Security Misconfiguration > Unsafe Cross-Origin Resource
Sharing. **Correction from earlier in-session severity chat: this is
more realistically VRT-baseline P3 (medium), not the P2 I said in
conversation** -- WordPress nonces block most state-changing/write
abuse via this hole, and I never confirmed with a real account whether
any genuinely sensitive data is reachable through it, so the honest
range is P3 ($200-750) most likely, P2 ($750-2400) if they confirm
real sensitive exposure, or P4/$0 if they decide nothing sensitive is
reachable (P4/P5 are unpaid in this program).
**Also confirmed the identical CORS misconfig on
`48ertandler.wien.gv.at`** (same DRA plugin, same broken CORS) --
strongly suggests a platform-wide WordPress config across all the
city's WP sites, not a one-off. This was NOT filed as a separate
report (likely duplicate root-cause) -- **still open action**: add a
comment to the already-submitted Bugcrowd report noting it also
affects 48ertandler.wien.gv.at and is likely citywide, so the fix
lands on the shared config rather than one site. I had offered to do
this and was waiting on a go-ahead when the session ended.

Host-by-host status (full detail in the notes file):
- `www.wien.gv.at` -- main portal, real search (`q` param on
  `/suche`+`/en/search`), full active-payload pack run clean (no
  findings after ruling out a WAF-block false positive on `' OR
  '1'='1'`). Well-defended.
- `wien.at` -- dead end, alias to www.wien.gv.at.
- `www.gesundheitsverbund.at` -- alias to gesundheitsverbund.at
  (apex), not yet followed up.
- `www.akhwien.at` -- hospital site, real ASP.NET search forms
  (searchtext/searchdocument etc, pid/mid/rid/did routing). Active
  payload run: one CRLF-reflection lead, manually chased into a
  confirmed-but-unexploitable reflected-XSS attempt (unescaped
  `value='...'` attribute reflection, but single quotes get silently
  stripped server-side AND the WAF blocks common event-handler
  keywords -- two independent defenses, dead end).
- `wibi.wien.gv.at` -- live, not yet explored.
- `mein.wien.gv.at` + its API -- citizen portal, needs a real login,
  not pursued (no account).
- `stp.wien.gv.at` -- "Standardportal" city SSO, needs auth, not
  pursued.
- `digitales.wien.gv.at` -- WordPress, **CORS finding submitted** (see
  above). wp-login.php/xmlrpc.php/readme.html all WAF-blocked (403,
  "MA 01 - Wien Digital" block page) -- good hardening otherwise.
- `48ertandler.wien.gv.at` -- WordPress, **same CORS bug confirmed**,
  not separately filed (see above -- still need to comment on existing
  submission).
- `www.geschichtewiki.wien.gv.at` -- MediaWiki 1.43.9 (recent, well
  patched) + Page Forms/Semantic MediaWiki extension. Only info-level
  cookie hygiene findings on the login page. Would need a self-serve
  wiki account (open registration) to test the actual edit/upload
  flows -- not created (account creation is something the user does,
  not something I do).
- `stadtservicebot.wien.gv.at` -- tiny chatbot widget shell, 2 pages,
  already has good headers. Low value.
- `scds.dev.handbuch.wien.gv.at`, `cms-wien.magwien.gv.at` -- both
  appear internal-only / not reachable from the public internet
  despite resolving in DNS (TLS handshake fails/aborts). Not
  practically testable.
- Untouched so far: `search.wien.gv.at` (400 on a bare GET, needs a
  real query param), `start.wien.gv.at` (live, not explored), the
  `pulsepoint.com`-style network ranges/Azure tenants/mobile apps
  listed in scope (see notes.md for the full list) -- none of these
  were touched this session.

## Shroodler bugs found + fixed this session

All have regression tests and the full suite passes after each
(`python -m pytest packages/crawler-py/tests` and
`python -m pytest packages/payload-tester/tests`). Rebuild with
`make install-cli` after pulling/making changes.

1. **Custom-element form fields silently dropped.**
   `packages/crawler-py/shroodler/extractors/forms.py` -- only
   recognized `<input>`/`<select>`/`<textarea>`, missing modern
   Web-Component form fields (e.g. `<wm-input name="q">` on
   www.wien.gv.at). Fixed: also matches any tag with a hyphen in its
   name (the Custom Elements spec requires this). Tests:
   `test_custom_element_field`,
   `test_anchor_inside_form_not_treated_as_field` in
   `packages/crawler-py/tests/unit/test_forms.py`.

2. **Payload tester fired the full pack once per page a form appeared
   on, not once per unique target.** `packages/payload-tester/tester.py`
   -- a header search box present on all 24 crawled pages of
   www.wien.gv.at got the entire 39-payload pack fired 24x (~700+
   requests, would've taken over an hour at the self-throttled rate).
   Fixed: dedup by `(method, absolute action, sorted field names)`
   before firing any request. Test:
   `test_same_form_action_across_many_pages_is_tested_once` in
   `packages/payload-tester/tests/test_tester.py`.

3. **ASP.NET `__VIEWSTATE`/`__EVENTVALIDATION` flagged as a possible
   leaked API key.** `packages/crawler-py/shroodler/extractors/secrets.py`
   -- these are naturally high-entropy base64 blobs (framework postback
   state, not secrets), spamming false positives on every classic
   ASP.NET site (seen on www.akhwien.at, would also affect
   exchange.pulsepoint.com from the Internet Brands program). Fixed:
   excludes tokens that fall inside a `name="__VIEWSTATE"`/
   `__EVENTVALIDATION` field's own `value="..."` span specifically
   (not a flat lookbehind window -- verified a real secret sitting
   right after such a field still fires). Test:
   `test_aspnet_viewstate_is_not_a_secret_hit` in
   `packages/crawler-py/tests/unit/test_secrets.py`.

4. **A failed fetch (connection/TLS error) reported "every security
   header is missing."** `packages/crawler-py/shroodler/crawler.py`
   (`page_from_fetch`) -- `status_code=0` on a genuinely unreachable
   host (e.g. scds.dev.handbuch.wien.gv.at) still ran header analysis
   against an empty headers dict, manufacturing 5 false
   missing-header findings out of "we never got a response." Fixed:
   skip header analysis entirely when `status_code == 0`. Test:
   `test_failed_fetch_reports_no_missing_header_findings` in
   `packages/crawler-py/tests/unit/test_cookies.py`.

## Known false-positive patterns NOT yet fixed (lower priority, logged)

- `exposed-file: high` fires on `/.well-known/security.txt` -- that
  file is *supposed* to be public (RFC 9116), not a vuln. Seen on
  portalv2.lh360.com.
- Long opaque tokens embedded in URLs (map bookmarks, tracking IDs)
  trip the `generic-api-key` entropy check with no reliable
  known-field-name signal to exclude them the way the ViewState fix
  did. Seen on www.akhwien.at (`bookmark=` param on a city-map link).
  Logged in `docs/roadmap.md` under "Session-driven ideas" -- needs a
  more careful heuristic than a quick patch, not attempted this
  session.
- `waf-challenge-sitewide` finding shows a nonsensical ratio like
  "18/1 pages challenged" (numerator counts probe-URL challenge hits
  that aren't in the `pages` count used as denominator). Seen on
  demandforced3.com (Internet Brands program). Not fixed.

## Roadmap additions this session

`docs/roadmap.md` gained a new "Session-driven ideas (from live
bug-bounty dogfooding)" section with two entries, both flagged
Recommended by the user to build next:

1. **Scope triage sweep** (`shroodler triage <hosts>`) -- one fast
   pass classifying every host in a program's scope as
   redirect-alias / WAF-challenge-gated / SSO-gated / live-content /
   dead, before spending crawl budget. Directly motivated by how much
   manual `curl -I` triage this session needed across ~15 hosts.
2. **Auth-stack fingerprinting + standard probe library** -- detect
   next-auth (and later Keycloak/Auth0/generic OAuth) by cookie/path
   signature and auto-run the known-pattern checks (e.g. the
   `callbackUrl`-into-cookie check that surfaced the unauthenticated
   lead on portalv2.lh360.com), instead of reconstructing the curl
   sequence by hand each time.

Also logged the URL-embedded-token false-positive class (see above)
as a lower-priority roadmap entry in the same section.

## Suggested next actions, roughly in priority order

1. Add the "also affects 48ertandler.wien.gv.at, likely platform-wide"
   comment to the already-submitted Vienna CORS report (user was
   deciding on this when the session ended).
2. Check on PlanetHoster credentials; if arrived, start there --
   highest reward ceiling of the programs actually reachable, and the
   IDOR/BAC focus area is a great fit for Shroodler's `authz-diff`.
3. Self-register the ThousandEyes account if still interested in that
   program (remember: manual testing style only, no automated scans).
4. Otherwise, keep working City of Vienna: `search.wien.gv.at` (needs
   a real query to get past its 400), `start.wien.gv.at`,
   `wibi.wien.gv.at` are the remaining untouched-but-reachable hosts.
   Self-serve a `@bugcrowdninja.com` wiki account to properly test
   geschichtewiki's Page Forms extension if going deeper there.
