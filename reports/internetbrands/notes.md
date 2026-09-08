# Internet Brands Public — working notes

Program: https://bugcrowd.com/engagements/internetbrands-public
Rewards: P1 $2000 / P2 $750 / P3 $100. Safe harbor in place.
Excluded: missing security headers, clickjacking, sub-P2 XSS, login
brute-force/enumeration, SSL config issues, OPTIONS enabled, etc. (see
program brief for full list). XSS-severity-capped hosts: profreg/login
.medscape.com, powerpak.com, globalacademycme.com, mdedge.com.

## Targets tried

- pets.webmd.com — dead end, just a 301 alias to www.webmd.com/pets.
- accounts.webmd.com — dead end, just a 301 alias to member.webmd.com.
- portalv2.lh360.com (Lighthouse360+, Henry Schein One / B2B practice
  software, Next.js + next-auth, Keycloak SSO at loginv2.lh360.com):
  - Fully gated behind SSO (Keycloak realm `lh360`, client `bp-lh360`,
    PKCE S256) and a credentials provider `HOP-PP-LOGIN`. No
    unauthenticated forms/params to test directly.
  - **Unconfirmed lead**: `/api/auth/signin?callbackUrl=<url>` and
    `/api/auth/signin/HOP-PP-LOGIN?callbackUrl=<url>` accept an
    arbitrary external URL and store it unvalidated in the
    `__Secure-next-auth.callback-url` cookie (confirmed via curl,
    2026-09-07). This is the classic setup for a NextAuth
    post-login open redirect, but NextAuth's default `redirect()`
    callback blocks external URLs unless the app overrode it — so
    real impact (does a successful login actually redirect to the
    attacker URL?) is UNCONFIRMED. Verifying requires a logged-in
    session; user decided not to pursue getting a test account for
    this program, so this lead is parked, not submitted anywhere.
    Program brief also says "All targets are publicly accessible and
    do not require any additional steps to access" — read as a signal
    this program doesn't expect/provide test accounts.

## Shroodler bugs found and fixed along the way

- Headless crawler (`packages/crawler-py/shroodler/modes/headless.py`):
  a page that client-side-redirects (JS/SSO) to a different origin was
  being treated as a normally-visited same-origin page — content and
  discovered links were extracted from the off-origin page, and it got
  revisited/looped once per distinct in-scope seed URL that redirected
  there (observed: 6x reprocessing of an out-of-scope
  henryscheinone.com page reached from portalv2.lh360.com). Fixed by
  checking `same_origin(page.url, requested_url)` right after
  navigation and short-circuiting to a redirect-only FetchResult if it
  landed off-origin.
- `crawler.py` shared crawl loop: added an `off-origin-redirect-not-followed`
  info finding whenever a redirect target isn't same-origin, so this is
  now visible in reports instead of silently dropped (applies to both
  static and headless modes).
- `exposed-file` detector flags `/.well-known/security.txt` as a
  finding — that's a false positive, the file is meant to be public
  (RFC 9116). Not yet fixed in code.
- `generic-api-key` secret detector flagged Next.js build-hash
  filenames (e.g. `_next/static/chunks/...-<hash>.js`,
  `_buildManifest.js` contents) as possible API keys on
  portalv2.lh360.com. False positives, not yet fixed in code.
