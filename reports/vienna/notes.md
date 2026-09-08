# City of Vienna Managed Bug Bounty — working notes

Program: https://bugcrowd.com/engagements/city-of-vienna-mbb-og
Rewards: P1 $2400-3500 / P2 $750-2400 / P3 $200-750. Safe harbor in place.
**No public disclosure allowed** — do not publish writeups/findings
anywhere outside Bugcrowd.
Excluded: P4, P5, CSRF, no-rate-limiting, DMARC/DKIM/SPF, request
smuggling (temporarily, being fixed centrally).
N-day policy: public N-days in scope only after 21 days from disclosure.

## Scope (concrete hosts, non-wildcard)

- www.wien.gv.at (jQuery, known issues: 20)
- stp.wien.gv.at (known issues: 8)
- wien.at (known issues: 2)
- www.gesundheitsverbund.at (WordPress, known issues: 0)
- www.akhwien.at (known issues: 1)
- Mein Wien: https://mein.wien.gv.at/ (citizen portal, known issues: 4) —
  likely needs a real citizen/test account to get past login
- Mein Wien API: https://mein.wien.gv.at/broker/api/* (API Testing,
  known issues: 4)
- Wibi: https://wibi.wien.gv.at/ (known issues: 2)
- FTAPI Gesundheitsverbund: https://secumails.gesundheitsverbund.at
  (secure mail portal, known issues: 1)

## Scope (wildcards — only testable once a concrete subdomain is found)

*.wien.gv.at (64 known issues — clearly the most active/highest-value
wildcard), *.magwien.gv.at (2), *.gesundheitsverbund.at (10),
*.wienkav.at (0), *.akhwien.at (1), *.wien.at (5)

## Scope (non-web)

- Azure AD tenants: *.stadtwien.onmicrosoft.com, schulenwien.onmicrosoft.com
- SharePoint Online: stadtwien-my.sharepoint.com
- Network ranges: 141.203.0.0/16, 217.149.224.0/20, 2a00:1ba0:2::/48,
  2a00:1ba0:3::/48, 217.116.64.0/20 (AS6720 / AS16314)
- Mobile: City of Vienna Android (Play Store) and iOS apps

## Out of scope

- https://www.wien.gv.at/advuew/*
- Public Network / Veranstaltungsnetz 141.203.188.0/22

## Access

Self-serve account signup via @bugcrowdninja.com email, no manual
review/waiting (unlike PlanetHoster). Most public www.* sites need no
account at all for unauthenticated testing.

## Shroodler bugs found here

- Form-field extraction only recognizes plain `<input>`/`<select>`/
  `<textarea>`. www.wien.gv.at's search box is a custom web component
  (`<wm-input name="q">`, part of their "Wiener Melange" design system)
  — the crawler found the `<form action="/suche">` but reported zero
  fields/params, completely missing the real `q` GET parameter. Modern
  sites increasingly use custom elements for form controls; worth
  extending the extractor to also look for a `name` attribute on any
  element inside a `<form>`, not just the classic form-control tags.
  **Fixed** in packages/crawler-py/shroodler/extractors/forms.py: now
  also matches any tag whose name contains a hyphen (the Custom
  Elements spec requires this, so it's a precise signal rather than
  "any element with a name attribute" which would misfire on things
  like `<a name="anchor">`). Verified against www.wien.gv.at: the `q`
  param on both `/suche` and `/en/search` is now correctly extracted.
  Tests added in test_forms.py; full crawler-py suite passes (541
  passed, 1 skipped).

- Payload tester (`packages/payload-tester/tester.py`) had a serious
  request-volume bug: it fired baseline + full pack **once per crawled
  page** a form appeared on, with dedup only happening afterward at the
  *finding* level (line ~601), not before firing requests. www.wien.gv.at's
  header search box (`/en/search?q=`) appears on all 24 crawled pages,
  so a single real injection point got the full 39-payload pack fired
  24 times — ~700+ live requests against a government server for one
  endpoint, at ~4s/request (self-throttled) that would have taken over
  an hour. Caught mid-run (34+ min in, request count climbing far past
  expected) and killed before completion.
  **Fixed**: added a `tested_targets` set keyed on
  (method, absolute action, sorted field names), checked before firing
  baseline/payloads, so each unique target is only tested once no
  matter how many pages it was seen on. Regression test added
  (`test_same_form_action_across_many_pages_is_tested_once`); full
  payload-tester suite passes (51 passed) and the broader non-crawler
  suite passes (165 passed).

## Active payload results (www.wien.gv.at, after the dedup fix)

Ran clean: 103 requests total (2 unique targets: /suche, /en/search),
finished in under a minute. One finding,
`payload-sql-status-change` (confidence: confirmed, but the pack's own
description says "weak signal") on `' OR '1'='1` -- manually verified
via curl and it's a **false positive**: the site's WAF returns a 403
"Zugriff verweigert / Forbidden" page for that exact string (baseline
200 vs payload 403, but it's the firewall blocking the SQLi-shaped
input, not a real DB error). Not reportable.

No other findings from the full pack (SQLi/XSS/SSTI/path-traversal/
SSRF/open-redirect/XXE/command-injection/CRLF) against the `q`
parameter on either endpoint.

## www.akhwien.at (AKH Wien hospital site)

25-page crawl: classic ASP.NET WebForms app (default.aspx?pid=N, also
mid/rid/did params), real search modules (searchtext/searchdocument,
btnSearchAmbulance), calendar module.

- Fixed another systemic false positive:
  `packages/crawler-py/shroodler/extractors/secrets.py`'s
  `generic-api-key` entropy detector was flagging ASP.NET's own
  `__VIEWSTATE`/`__EVENTVALIDATION` postback state (naturally
  high-entropy base64, but framework plumbing round-tripped to the same
  client, not a secret) on nearly every page of every classic ASP.NET
  site -- this one, and PulsePoint's exchange.pulsepoint.com from the
  earlier Internet Brands program too. **Fixed**: now matches the
  specific `value="..."` span of a `name="__VIEWSTATE"`/
  `__EVENTVALIDATION` field and excludes only tokens inside that span
  (not a flat lookbehind window -- a real secret sitting in nearby
  markup right after a ViewState field still fires normally, verified
  by test). Regression test added
  (`test_aspnet_viewstate_is_not_a_secret_hit`); full crawler-py suite
  passes (542 passed, 1 skipped). Re-crawled www.akhwien.at after the
  fix: no more `wEPD...`-prefixed (ViewState) hits.
- Remaining `generic-api-key` hits on this site (24 of them) are a
  *different*, fuzzier false-positive class: long opaque tokens
  embedded in URLs that are legitimately high-entropy but not secrets
  -- e.g. `bookmark=KSJE...pr4C` on a city-map link
  (grafik.aspx?...&bookmark=...). Unlike ViewState there's no reliable
  "known field name" signal to key off here (a URL query param *could*
  legitimately carry a real leaked token in some other case), so this
  needs a more careful heuristic than a quick patch -- logged as a
  roadmap idea, not fixed this session.
- No SQLi/XSS/etc. findings yet -- haven't run the active payload
  engine against this site's search fields
  (searchtext/searchdocument/btnSearchAmbulance) yet.
- One real, low-severity finding: `cookie-path-broad` (not yet
  reviewed in detail).

## digitales.wien.gv.at (found via CSP-header subdomain mining under *.wien.gv.at)

WordPress (Enfold/wienat_enfold theme, WPML 4.9.5, Formidable Forms Pro).
wp-login.php/xmlrpc.php/readme.html all blocked by the city's WAF (MA01
block page) -- good hardening. REST API (/wp-json/) requires auth
site-wide via a "DRA" hardening plugin (401 for anonymous requests).

**Real finding, draft written**: CORS misconfiguration across the entire
/wp-json/ REST API -- reflects arbitrary Origin + Access-Control-Allow-
Credentials: true on every route tested (root, wp/v2/users, oembed, and
an OPTIONS preflight against wp/v2/users/me). Anonymous reads return 401
(the DRA plugin), but the CORS hole itself remains live for any
authenticated editor/admin session -- their browser would attach real
session cookies to a cross-origin request from a malicious page, which
could then read the response. Draft submission written to
digitales-cors-report.md, sent to user, NOT submitted yet. Suggested VRT:
CORS misconfiguration w/ credentials, ~P2.

Other in-scope hosts found under this domain not yet explored: 48ertandler.wien.gv.at
(live, real content), search.wien.gv.at (400 on plain GET, needs a real
query), start.wien.gv.at (live), www.geschichtewiki.wien.gv.at (redirects
to a MediaWiki instance), stadtservicebot.wien.gv.at (chatbot, live),
scds.dev.handbuch.wien.gv.at (a *dev* subdomain -- handbook/docs, live).
cms-wien.magwien.gv.at appears unreachable externally (likely internal-only).

## Plan

1. Passive/unauthenticated recon first, no account needed: www.wien.gv.at,
   wien.at, stp.wien.gv.at, www.gesundheitsverbund.at, www.akhwien.at,
   wibi.wien.gv.at.
2. If subdomain discovery during crawling turns up real hosts under the
   wildcard domains, those are in-scope too — worth deliberately looking
   for (sitemap, JS asset hosts, SPF/mail records won't count since
   DMARC/SPF is excluded, but subdomain enumeration via crawl-discovered
   links is fair game).
3. Mein Wien portal + API need a real account — flag to user when
   reached, same as PlanetHoster/ThousandEyes.

## Update 2026-09-07 (session 2)

- **Citywide CORS comment SENT** on the digitales.wien.gv.at submission
  (Bugcrowd id 1cc98209-dc73-4dc7-a890-c82531cb80b3). Noted the
  byte-identical /wp-json/ CORS misconfig on 48ertandler.wien.gv.at,
  recommended a shared-config-layer fix. This clears the last open
  action from the session-1 handoff.
- Remaining reachable hosts cleared as dead ends for an in-scope finding:
  - search.wien.gv.at: returns 15-byte "400 Bad Request" to every
    path/param/method tried -- internal-API-shaped, not publicly fuzzable.
  - start.wien.gv.at: Liferay portal (JSON-WS /api/jsonws disabled ->
    404, /c/portal/layout 302). Search at /suche?q= is the shared
    Wiener-Melange search and is context-aware encoded (value="..." attr
    escapes " -> &quot;; <strong> results text escapes <>; JS string
    percent-encodes) -- no XSS. Same defense posture as www.wien.gv.at.
  - wibi.wien.gv.at: static AngularJS+Kendo SPA whose backend
    (config.json baseURL) is the THIRD-PARTY api.schoolfox.com -- out of
    program scope. In-scope host has no own dynamic surface.
- **Operational lesson**: a mass /wp-json/ CORS sweep across all ~1207
  *.wien.gv.at crt.sh subdomains (8-way, then 4-way parallel) saturated
  the local mihomo proxy (127.0.0.1:7897) AND tripped the city WAF into
  rate-limiting the source IP -- known-good hosts started returning no
  response. Do NOT mass-scan wien.gv.at. Two cleanly-confirmed identical
  instances were already enough evidence. Host list saved for reference
  in scratchpad wien_hosts.txt (1207 hosts).

## Update 2026-09-07 (session 3 — Gesundheitsverbund)

Program reconfirmed **In progress**, scope 4/4. Brief Details pane is
still a loading skeleton under the Playwright debugger, so this pass
used the previously captured target list.

### Recon (passive then gentle)

- crt.sh timed out inside `shroodler triage --discover` (8s client
  timeout). Direct crt.sh + certspotter fetches worked: **140** unique
  `*.gesundheitsverbund.at` names. DNS-only triage: 95 resolve, 45 dead,
  **0 takeover candidates**. HTTP classification at concurrency 2 / 1 rps
  (no zone pause): 30 live-content, 55 in-scope redirect aliases, 10
  errors/timeouts. Lists:
  `hosts-gesundheitsverbund-ct.txt`,
  `triage-dns-gesundheitsverbund.json`,
  `triage-http-gesundheitsverbund.json`.
- `www.gesundheitsverbund.at` 301s to apex `gesundheitsverbund.at`
  (WordPress / Enfold, same family as digitales).

### WordPress farm — CORS is the same finding, do not refile

Sampled sequentially (not a farm sweep): apex, campus-alsergrund,
einkauf, karriere, klinik-ottakring, pflege.

Every `/wp-json/` response reflects `Origin: https://evil.example.com`
and sends `Access-Control-Allow-Credentials: true`. `/wp/v2/users` is
401 DRA ("Nur authentifizierte Benutzer…") on all of them.

Nuance vs digitales:
- Apex / klinik / karriere: `/wp-json/` itself is also 401 DRA.
- campus-alsergrund, einkauf, pflege: `/wp-json/` index is **200**
  (site name + plugin namespaces). Still not user enum.
- Session cookie `stdpsession*` is `Secure; HttpOnly; SameSite=None`
  (load-balancer / Stadt-portal affinity, not WordPress auth).
  `PHPSESSID` on the apex homepage is `SameSite=Lax`. So the CORS
  credentials flag is real, but the cookie that actually looks like
  PHP/WP session is Lax — same calibration as the digitales report:
  impact is an authenticated editor/admin in a browser, not anonymous
  data theft. **Comment on
  1cc98209-dc73-4dc7-a890-c82531cb80b3 rather than a new report.**

Plugin REST: `frm-admin/v1` and `real-media-library/v1` indexes return
200 even on the DRA-locked apex (namespace map only). Advertised
`/frm-admin/v1/install` and `install-addon` are nginx **403**. Forms/
entries routes 404. xmlrpc.php 403. Not a separate bounty finding.

### Do not submit the greeting-card or contact forms

`/digitale-grusskarte/` is a Formidable Pro form that sends a card to a
**patient/resident + ward**. `/kontakt/` emails staff and has reCAPTCHA.
Both are out for this pass (third-party patients; no CAPTCHA solving;
no spam).

### Other live apps (all login-gated or public-by-design)

- **secumails.gesundheitsverbund.at**: FTAPI, redirects to login.
  `/webui/` and `/ftapi/` → `/login?continue=…`. No account created.
- **3dhisto**: 3DHISTECH SlideCenter, `/SlideCenter/Login` only.
  swagger/api 404.
- **arex**: AREX web, `/ArexWeb/Account/Login`. VersionInfo is a public
  JSON modal (P5 fingerprint).
- **webmail**: Citrix Gateway (`/logon/LogonPoint/`, `NSC_TASS`).
  `NSC_TMAP=al2-webmail.wienkav.at` internal name — not reportable.
- **ma70bp**: "Standardportal - Stammportal" login; `/login` `/idp` 403.
- **static.gesundheitsverbund.at**: empty 200, `Access-Control-Allow-Origin: *`
  without credentials. Header-only, skip.
- **physik**: static medical-physics HTML.
- **bp.gesundheitsverbund.at**: Bildungsprogramm 2.45.1.0 (EasyUI).
  Public course search `GET /bildungsprogramm/Kurse/SearchForKurse` and
  `Home/SearchForNaechsteKurse` returns course titles/locations/KursID.
  Catalog is meant to be public; `AnmeldungIntranet: true`. Crawler
  burned its page budget on CSS/JS (0 HTML forms). `generic-api-key`
  hits are false positives (modernizr/jquery license URLs).

### Shroodler bug this pass

`extractors/tls.py` emits `category: "tls"` (already in
`models.py` / tests) but `schema/finding.schema.json` omitted `tls`
from the enum, so a finished 40-page crawl of gesundheitsverbund.at
failed at `validate_crawl` and wrote nothing. Added `tls` to the
schema enum. Bildungsprogramm crawl after the fix saved normally.

### Next (if continuing Gesundheitsverbund)

- Authenticated FTAPI / SlideCenter / AREX / Standardportal need
  operator-provided test accounts — do not self-register.
- Bildungsprogramm: one EasyUI datagrid search is enough unauth;
  enrollment is intranet-flagged.
- Optional: paste a follow-up comment on the digitales CORS ticket
  listing the Gesundheitsverbund WP hosts as the same shared CORS
  layer (SameSite=None affinity cookie + reflected Origin + ACA-Credentials).

## Update 2026-09-07 (session 4 — unauth, not Gesundheitsverbund)

Left login-gated apps. Stayed on City of Vienna (still In progress;
Playwright MCP timed out so a different program's brief could not be
re-read safely). Target: `*.wienkav.at` (0 known issues) plus a
**curated** 10-host sample of `*.magwien.gv.at` — not a 367-host sweep.

### `*.wienkav.at`

- 173 CT names (plus one email SAN stripped). DNS: **154 dead / 19
  resolve / 0 takeovers**. The old KAV zone is almost entirely
  decommissioned.
- Shroodler HTTP triage paused the whole zone after autodiscover
  timeouts (false WAF pause). Manual sequential GETs:
  - `bp.wienkav.at` → `bp.gesundheitsverbund.at` (already crawled)
  - `webmail.wienkav.at` → GV Citrix webmail
  - `ma70bp.wienkav.at` → Standardportal 403 (auth)
  - `remote.wienkav.at` → Citrix Gateway `/logon/LogonPoint/`
  - apex TLS SNI fail; ribm/datagate/testdatagate/grvpn/cc-health/cs-health
    timed out
- No live unauthenticated content. Matches "0 known issues."

### `*.magwien.gv.at` (curated only)

CT has 367 names (lots of Tekton/cms-wien internals). Only these 10
were probed: confluence, cms-wien, cmsadmin-t.host, charta,
gisapublic, erecht, elak, dx, hera, hyzdok.

- 7 dead (including confluence / cms-wien).
- `erecht.magwien.gv.at` CNAME → `erecht.wien.gv.at` NXDOMAIN.
  Shroodler flagged takeover; **not claimable** (points at another
  in-scope city zone, not a SaaS vendor). Do not report.
- `dx.magwien.gv.at` → `www.intern.magwien.gv.at/...` → Standardportal
  403.
- `hyzdok.magwien.gv.at` live Azure Front Door SPA ("HyzDok").
  `robots.txt` is `Disallow: /`. Homepage is an empty React shell.
  `/health` returns ASP.NET health JSON (`Database` / `SQL Server`
  Healthy) — fingerprint only, **P5 / unpaid**, no connection
  strings. `/hangfire` is 401. Swagger 404. Not drafted.

### Unauth Vienna leftover that is actually live is mostly SSO.

Further unauth hunting on this program is low EV unless picking
individual leftover `*.wien.gv.at` CMS hosts (and those CORS-clone).
A different enrolled program needs a live Bugcrowd brief re-read.
