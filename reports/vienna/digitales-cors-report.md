# CORS misconfiguration on the entire WordPress REST API — digitales.wien.gv.at

**Program:** City of Vienna Managed Bug Bounty (Bugcrowd)
**Target:** https://digitales.wien.gv.at (in scope under the `*.wien.gv.at`
wildcard target)
**Suggested VRT:** CORS Misconfiguration — Arbitrary Origin Reflected With
Credentials Enabled (typically P2)
**Note on scope:** this program does not exclude CORS findings.

## Summary

Every route under `https://digitales.wien.gv.at/wp-json/` (the site's
WordPress REST API) reflects an arbitrary attacker-controlled `Origin`
request header back as `Access-Control-Allow-Origin`, and additionally
sends `Access-Control-Allow-Credentials: true`. This combination tells
browsers it is safe to send credentials (cookies) on a cross-origin
request to this API from *any* website, and to let that website's script
read the response.

Anonymous access to the REST API is itself blocked by a hardening plugin
(`401 rest_cannot_access`, "DRA: Nur authentifizierte Benutzer können auf
die REST-API zugreifen"), so an anonymous visitor gets nothing useful.
That does **not** fix the CORS hole — it only means the practical impact
is scoped to authenticated users (content editors/admins of this site),
who are exactly the population whose data and actions matter most.

## Steps to reproduce

1. Send a request to any REST route with an arbitrary `Origin` header:

   ```
   curl -H "Origin: https://evil.example.com" \
     https://digitales.wien.gv.at/wp-json/wp/v2/users
   ```

   Response headers (trimmed):

   ```
   access-control-allow-origin: https://evil.example.com
   access-control-allow-credentials: true
   access-control-allow-methods: OPTIONS, GET, POST, PUT, PATCH, DELETE
   ```

2. Confirmed this is not limited to one endpoint — the same reflected
   Origin + credentials=true was observed on:
   - `/wp-json/` (API root)
   - `/wp-json/wp/v2/users`
   - `/wp-json/oembed/1.0/embed?url=...`
   - An `OPTIONS` preflight against `/wp-json/wp/v2/users/me` returns the
     same headers, meaning a real cross-origin `fetch(..., {credentials:
     'include'})` from any page would pass the browser's CORS preflight
     check.

3. Body content for unauthenticated requests currently returns a 401
   (blocked by a separate hardening plugin) — this was not bypassed and
   is not part of this report. The vulnerability is the CORS policy
   itself, which applies regardless of that plugin, and takes effect for
   any authenticated session.

## Impact

A logged-in editor or administrator of this WordPress site who visits an
attacker-controlled page (in another tab, or lured via a link) would have
their browser automatically attach their `digitales.wien.gv.at` session
cookie to a cross-origin request the attacker's page makes to
`/wp-json/...`. Because of this CORS policy, the attacker's page can read
the JSON response — exposing whatever that authenticated session can see
via the REST API (user info, draft/private content, site configuration,
etc., depending on the user's role and which REST routes are registered).
Depending on which REST routes accept state-changing methods under
cookie-based auth without additional CSRF-nonce enforcement, this could
extend beyond read access.

This requires an authenticated victim to visit an attacker page while
logged in — not remotely exploitable against anonymous visitors — but
needs no special access or social engineering beyond a normal malicious-
link/drive-by scenario.

## What I did not verify

I did not have a WordPress account on this site (no test credentials
provided by the program for this target), so I could not log in and
confirm exactly what data a real authenticated session would expose via
this CORS hole, or test whether any REST route accepts state-changing
requests under cookie auth without a nonce. The misconfiguration itself
(arbitrary-origin reflection + credentials=true, applied API-wide) is
fully confirmed and reproducible without authentication.

## Suggested fix

Stop reflecting arbitrary `Origin` values. Either send a fixed, narrow
`Access-Control-Allow-Origin` (or omit CORS headers entirely if
cross-origin REST access isn't actually needed), or validate `Origin`
against an explicit allowlist before echoing it back — and do not combine
a reflected/wildcard origin with `Access-Control-Allow-Credentials: true`
under any circumstance.
