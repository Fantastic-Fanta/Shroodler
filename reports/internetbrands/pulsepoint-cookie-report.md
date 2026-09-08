# Sensitive cookies (incl. auth ticket) missing Secure/HttpOnly, broadly domain-scoped — exchange.pulsepoint.com

**Program:** Internet Brands Public (Bugcrowd)
**Target:** https://exchange.pulsepoint.com (in scope, tag: "Website Testing")
**Suggested VRT:** Sensitive Cookie Without 'Secure' Flag (P4) / Sensitive
Cookie Without 'HttpOnly' Flag (P4)
**Note on scope:** this report is about cookie attributes on sensitive
(session/auth) cookies, which the program brief does not exclude — it only
excludes missing flags on *non-sensitive* cookies. Missing HSTS is cited
below only as supporting context for exploitability, not as a separate ask
(the brief does exclude missing-security-header reports on their own).

## Summary

`https://exchange.pulsepoint.com/AccountMgmt/Login.aspx` sets four cookies,
none of which carry the `Secure` attribute — including
`CWAuthTkt_CROSS_DOM`, which by name and cross-domain scoping is the site's
authentication ticket, and `ASP.NET_SessionId_CROSS_DOM_custom`, the ASP.NET
session identifier, which is also missing `HttpOnly`. All four are scoped
`Domain=.pulsepoint.com`, i.e. sent to every `*.pulsepoint.com` host, not
just `exchange.pulsepoint.com`.

Because these cookies aren't marked `Secure`, a browser will attach them to
a plain `http://` request to any `*.pulsepoint.com` host if one is ever
made. The site does not send an HSTS header, and plain HTTP requests are
accepted (server issues a redirect rather than refusing the connection) —
so nothing on the client or server side prevents that from happening.

## Steps to reproduce

1. Request the login page and inspect the `Set-Cookie` headers:

   ```
   curl -sI https://exchange.pulsepoint.com/AccountMgmt/Login.aspx
   ```

   Response (trimmed to relevant headers):

   ```
   HTTP/2 200
   set-cookie: zacnkoertw=; domain=.pulsepoint.com; path=/; HttpOnly; SameSite=Lax
   set-cookie: ASP.NET_SessionId_CROSS_DOM_custom=ed423fc5-c576-4051-a807-105164ece25a; domain=.pulsepoint.com; path=/
   set-cookie: CWAuthTkt_CROSS_DOM=; domain=.pulsepoint.com; path=/; HttpOnly; SameSite=Lax
   set-cookie: ASP.NET_SessionId_CROSS_DOM=nm3epaqhua4ldm3owboizaie; domain=.pulsepoint.com; path=/; HttpOnly; SameSite=Lax
   ```

   Note: none of the four `Set-Cookie` headers include `Secure`.
   `ASP.NET_SessionId_CROSS_DOM_custom` additionally lacks `HttpOnly`,
   making it readable by any JavaScript running in the page (increasing
   XSS impact, should one exist elsewhere in the app).

2. Confirm plain HTTP is accepted rather than refused (both on the target
   host and the parent domain the cookies are scoped to):

   ```
   curl -sI http://exchange.pulsepoint.com/AccountMgmt/Login.aspx
   # -> HTTP/1.1 308 Permanent Redirect, Location: https://...

   curl -sI http://pulsepoint.com/
   # -> HTTP/1.1 301 Moved Permanently, Location: https://...
   ```

3. Confirm no HSTS header is sent on the HTTPS response (already visible in
   step 1's headers — `strict-transport-security` is absent).

## Impact

An attacker positioned to intercept a victim's network traffic (public
Wi-Fi, compromised router, rogue AP, classic SSL-stripping-style MITM) can
capture these cookies — including the auth ticket — the moment the
victim's browser is induced to make one plain-HTTP request to any
`*.pulsepoint.com` host. Because there's no `Secure` flag and no HSTS to
force HTTPS-only behavior, nothing prevents that. A captured
`CWAuthTkt_CROSS_DOM` value would let the attacker impersonate the victim's
authenticated session without needing credentials.

This requires an active network-MITM position, so it is not remotely
exploitable on its own — rating it P4/Low rather than higher.

## What I did not verify

I did not have a test account for this program, so I was not able to log
in and confirm the live (non-empty) value of `CWAuthTkt_CROSS_DOM` after a
successful authentication, or observe its exact attributes at that point.
The `Set-Cookie` pattern above (no `Secure` on any cookie this endpoint
sets, consistently, pre- and post-auth-attempt) is the basis for expecting
the same to hold once the ticket carries a real session value.

## Suggested fix

Add `Secure` to all cookies set under `*.pulsepoint.com` (at minimum
`CWAuthTkt_CROSS_DOM` and both `ASP.NET_SessionId_CROSS_DOM*` cookies), add
`HttpOnly` to `ASP.NET_SessionId_CROSS_DOM_custom`, and consider narrowing
the `Domain` attribute to only the hosts that actually need cross-subdomain
session sharing.
