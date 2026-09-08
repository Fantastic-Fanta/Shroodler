# Tripadvisor Bug Bounty — working notes

Program: https://bugcrowd.com/engagements/tripadvisor-bb-og
Reward: $50 - $5,000 (P1). Safe harbor. Public disclosure: not stated here (assume no).
scopeRank 4/4.

## In scope
- Tier 1 (payment/wallet APIs, high value, likely auth-gated):
  api.production.cde.tamg.cloud, partnerapi{,1,2}.tapayments.com,
  walletproxy{,1,2}.tapayments.com
- Tier 2: www.tripadvisor.com (+ localized versions via header/footer),
  api.tripadvisor.com, service.platform.tripadvisor.com,
  gwapi{,1,2}.tripadvisor.com (GraphQL gateway)
- Tier 3: ANY publicly accessible Tripadvisor web asset/host (broad wildcard)
- Vacation Rentals (ACQUIRED BRANDS - softest, prioritize):
  rentals.tripadvisor.com, *.vacationhomerentals.com, *.holidaylettings.com,
  *.flipkey.com, *.niumba.com, *.housetrip.com, marlo.ext.tripadvisor.com
- Bokun: ONLY *.bokundemo.com, *.bokuntest.com (all other bokun.* OUT)
- Mobile: TA Android/iOS apps, VR Owner iOS app

## Out of scope (key rules)
- Missing HTTP security headers = OUT (CORS must show real impact, not header-only)
- IDOR in property-owner features = temporarily OUT
- Open redirects = OUT (unless impact beyond social engineering)
- DMARC/email misconfig on non-mail domains = OUT
- Excluded brands: CruiseCritic, TheFork/LaFourchette, JetSetter, SeatGuru,
  VIATOR, HelloReco
- Out subdomains: ir., careers., spotlight*, spotlight-dev., *.tripadvisor.cn,
  *.tripadviser.at, *.tripadvisoradexpress.*, *.tripadvisorwifi.*, taplus.*,
  tripadvisor(-)plus.*, *.experiences.zone, travelermail.com, *.tripadvisor.*/Trips,
  /Mobile*, /engineering, /WidgetEmbed-*
- Bokun: *.bokun.{com,io,is,eu,website,tools,team,app}, *.bokunmobile.website OUT
- content fraud, DoS, spam, social engineering, AI-system attacks

## Strategy
1. Passive crt.sh recon on acquired VR brands (softest) + tripadvisor.com.
2. Gentle SEQUENTIAL probing of interesting live hosts (CORS w/ impact, tech
   fingerprint, exposed panels/old software). NO mass parallel sweeps (learned
   from the wien.gv.at proxy/WAF saturation).

## Recon results (2026-09-07, session 2)

### Acquired vacation-rental brands (crt.sh + DNS + HTTP)
- HouseTrip: most subs dead DNS (admin./dev./internal./my./supply-api./
  mobile-app-api./affiliate./blog./help./support. = NXDOMAIN, no dangling
  CNAME => not takeoverable). www.housetrip.com is LIVE modern Next.js on
  Cloudflare (not the dead brand expected).
- niumba/vacationhomerentals/holidaylettings: www.* are static sites served
  from AmazonS3 origins behind CloudFront (origin bucket name hidden; direct
  bucket-name guesses don't resolve). ayuda.niumba.com + help.holidaylettings.com
  = 301 redirect stubs -> www.tripadvisorsupport.com (Zendesk-style help center).
  blog.niumba.com (185.61.97.80) + resources.vacationhomerentals.com (Fastly)
  did not answer HTTPS root in one try (retry later).
- Net: acquired-brand surface is mostly static/dead; limited soft dynamic surface.

### Flagship CORS (www.tripadvisor.com) — CONFIRMED but likely toothless
- Reflects ANY Origin (evil.example.com, attacker.tld, null) with
  Access-Control-Allow-Credentials: true on GET / (even on 403 bot-block resp).
- BUT observed cookies are SameSite=Lax (datadome) / unspecified=>Lax (TAUnique);
  no auth cookie seen unauthenticated. If the real session cookie is also Lax/
  Strict, cross-site credentialed reads won't carry it => not exploitable for
  authed data theft. Program also EXCLUDES header-only findings. => weak/likely
  known unless proven against an authed data endpoint with SameSite=None cookie
  (needs a TA login to validate). Not reported.

### Best remaining angle
- Tier-3 broad wildcard (any tripadvisor.com asset): careful subdomain
  enumeration -> triage for forgotten/legacy apps (WordPress/CMS/exposed panels)
  is the most likely path to a repeatable Vienna-style win. Needs a gentle,
  non-hammering triage pass (do NOT mass-parallel; learned from wien.gv.at).

## Update 2026-09-07 (session 3) — Brave Playwright MCP connected

Program re-read: **In progress**, safe harbor, UA must contain `bugcrowd`. Missing
headers / open redirects / property-owner IDOR remain out. Announcement still
points researchers at `tamg.cloud`.

### Bugcrowd account (gmaxresonance)
Three submissions all **Pending / still being assessed** — do not resubmit:
- City of Vienna CORS (`digitales.wien.gv.at`) — 1 comment
- Internet Brands PulsePoint cookie hygiene — auto P4
- LaunchDarkly webhook SSRF — 1 comment

PlanetHoster brief is **In progress** (scope rating 1/4) but the Details/Targets
pane stayed as a loading skeleton in this session, so credentials status is
unknown. Do not start PlanetHoster until the Get Credentials block is readable.

### Passive CT + `shroodler triage`
- `tamg.cloud`: 383 cert names, 188 resolve, 214 dead, **0 takeover candidates**.
  Lots of internal names (argocd, vault, airflow, jupyterhub, ambassador-admin)
  but they are not public apps.
- `flipkey.com`: 21 names. Help center = CloudFront; a few resolve; rest dead.
  No dangling CNAMEs.

Active probe (identifying UA, concurrency 2, 1 rps, ~40 hosts): almost every
`tamg.cloud` sample returned **403 Forbidden** (plain body, IP/WAF gated). The
two that were not 403 (`airflow.rex-wh.tamg.cloud`, `jupyterhub.dspe.tamg.cloud`)
are a Go `404 page not found` — no Airflow/Jupyter UI. Flipkey zone paused after
the first WAF/timeout (expected politeness). **Worth crawling: only
`https://www.flipkey.com/`.**

### www.flipkey.com (VR leftover, points-only)
Static S3+CloudFront sunset page (last-modified 2025-10-27): "Flipkey has closed
down" + `<meta http-equiv="refresh" content="5; url=https://www.tripadvisor.com">`.
No forms, no params, no JS app. Crawl findings were header-only + `Server:
AmazonS3` — **excluded**. Negative.

### Partner API (Tier 2, key from the brief)
- `developer-tripadvisor.com/home/` → CloudFront/S3 AccessDenied (403).
- Partner doc at `api.tripadvisor.com/api/partner/2.0/doc?key=…` is live
  (envoy). Root path 404 `NotFoundException` as expected. Not fuzzed further
  (program forbids interacting with live properties; test-property IDs only).

### Browser note
Attaching Playwright's debugger to Brave trips DataDome on
`www.tripadvisor.com` (403). Use Shroodler/curl with the bugcrowd UA for
HTTP checks; use the unaugmented Brave window for any Tripadvisor UI work.

### Net this pass
No reportable finding. tamg.cloud is a gated internal platform from the public
internet; Flipkey leftover is a splash page. Next: Tripadvisor **test
properties** (needs a `bugcrowd`-named account the operator creates), partner
API against those test IDs only, or switch to MyFitnessPal authenticated IDOR
if the two `@bugcrowdninja.com` sessions are available in Brave.
