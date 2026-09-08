# MyFitnessPal Bug Bounty — working notes

Program: https://bugcrowd.com/engagements/myfitnesspal-mbb
Status: In progress (active; pausedReason null, verified 2026-09-07).
Reward: $50 - $4,500. scopeRank 1.

## In scope
- *.myfitnesspal.com (Java / Ruby on Rails / Scala / NodeJS) — website wildcard
- Mobile apps (high priority): com.myfitnesspal.android, iOS id341232718
## Out of scope
- community.myfitnesspal.com + community-stage.myfitnesspal.com (Vanilla forums)
- any *.myfitnesspal.com NOT reachable / non-MFP properties
## Access
- Public; app signup via @bugcrowdninja.com email; 1mo Premium on request.

## Strategy
1. Passive crt.sh subdomain recon on myfitnesspal.com -> triage for forgotten/
   legacy hosts (old CMS, staging, admin, exposed panels). GENTLE sequential
   probing only (no mass-parallel; wien.gv.at proxy/WAF lesson).
2. Unauthenticated misconfig checks on live hosts (CORS w/ impact, exposed
   files/panels, old software). 
3. Authenticated IDOR/BAC later if a @bugcrowdninja account is created (user).

## Recon results (2026-09-07)
174 subdomains via crt.sh. 

### Subdomain takeover pass — NEGATIVE (no confirmed takeover)
- CNAME->3rd-party: images(->s3, bucket EXISTS/AccessDenied), support(->zendesk active),
  status(->statuspage active), account-billing(->stripe), app/link3(->appsflyer),
  link.*(->branch bnc.lt), preferences(->datagrail), integ image hosts(->cloudfront,
  normal 403 not dangling).
- ~12 campaign hosts CNAME->secure.pageserve.co. Most serve live landing pages (200).
  mealscan. and partner. return "Pageserver 404" (no page) BUT serve a VALID TLS cert
  for the hostname => domain still connected to MFP's PageServe account (unpublished,
  not orphaned) => not externally claimable. Not a takeover.
- 28 hosts fully NXDOMAIN (no A, no CNAME) => nothing to take over.

### Credentialed CORS — CONFIRMED misconfig, impact gated on auth (PROMISING)
- api.myfitnesspal.com reflects arbitrary Origin + Access-Control-Allow-Credentials:true
  (200 on /, also on /v2/* paths). www.myfitnesspal.com same.
- This is the DATA API (health/food-diary/profile) => higher sensitivity than a
  marketing page.
- Gate: exploitable only if the API authenticates via a SameSite=None COOKIE. Only
  cookies visible unauthenticated are anon-device-id (SameSite unset=>Lax) and __cf_bm
  (Cloudflare, None, not auth). Real session cookie only appears after login.
- NEXT: needs an authenticated @bugcrowdninja.com MFP session to determine (a) does
  api use cookie auth, (b) session cookie SameSite, (c) does an authed data endpoint
  reflect origin+credentials. If cookie-auth + SameSite=None => real cross-origin
  health-data theft (P2-P3). If Bearer-token auth => toothless (likely).
- Also enables authenticated IDOR/BAC testing (higher-value angle) via two accounts.

## Authenticated session (2026-09-07) — account 1 = Gmaxresonance (user_id 53495629499501)
- CORS on api.myfitnesspal.com: DEFINITIVELY not exploitable. /user/auth_token shows
  the API uses Bearer tokens (token_type:Bearer). Cross-origin pages can't obtain/use
  the token via the credentialed-CORS reflection => toothless. Lead dropped.
- api.myfitnesspal.com/v2/* with the web session's Bearer token -> 401 (needs the app's
  specific client headers; classic www app doesn't use this API). Deprioritized.
- IDOR target = cookie-authed www surface. /food/diary/<username> is username-addressable.
  Diary privacy model (Public/Friends/Private) is the classic MFP enforcement-gap spot.
- Blocker: unauthenticated curl to /food/diary/<username> hits a DataDome/CF bot
  challenge (403 "Challenge"), so privacy testing must run IN-BROWSER across 2 accounts.
- Accounts: acct1 gmaxresonance@bugcrowdninja.com (logged in, Brave). acct2
  gmaxresonance+2@bugcrowdninja.com (created; username TBD; not yet in a browser session).

## IDOR testing result (account1 -> account2 gmaxresonance2)
- Diary privacy ENFORCED: from acct1 session, /food/diary/gmaxresonance2 returns
  "This Food Diary is Private" (no entries leaked). Negative — good access control.
- acct2's private diary page does NOT embed acct2's user_id (only the viewer's id
  appears), so user_id-based data-endpoint IDOR probing needs acct2's id via its own
  session or a friend-search resolution. Not yet obtained.
- Net so far on MFP: takeover NEG, CORS NEG (Bearer API), diary-privacy IDOR NEG.
  Remaining untested: data/AJAX endpoints that might bypass privacy given acct2 id;
  friend/message features; the app.myfitnesspal.com React app + its API auth.
