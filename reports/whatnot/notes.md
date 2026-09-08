# Whatnot — HackerOne Engagement

**Program**: https://hackerone.com/whatnot  
**H1 username**: gmaxresonance  
**Started**: 2026-09-08

## Accounts

| Role | Email | User ID | Status |
|---|---|---|---|
| Owner (A) | gmaxresonance@wearehackerone.com | 71938723 | Active (logged in) |
| Peer (B) | gmaxresonance+peer@wearehackerone.com | 71938862 | Created; login fails ("Invalid credentials") |

Password for both: `Meonen@12345`

### User B login status
The account was created successfully (user_id 71938862 confirmed via GraphQL), but
`POST /sign-in` returns "Invalid credentials". The GQL `login` mutation is blocked on
web ("Update app to login."). Refresh token in session-b.json is expired. User B
needs to be logged in manually in the browser to get fresh cookies, then saved to
session-b.json.

## Scope

Core targets (all under *.whatnot.com):
- `https://www.whatnot.com` — SPA (Next.js + GraphQL)
- `https://api.whatnot.com` — REST API (not directly accessible; different cookie domain)
- `wss://www.whatnot.com/services/live/socket/websocket` — Phoenix live socket
- `wss://www.whatnot.com/services/auction/socket/websocket` — Phoenix auction socket

Rate limit per program rules: 100 req/s per endpoint, 10k req/day.

## Auth mechanism (confirmed)

Cookie-based. Key cookies on `www.whatnot.com`:

| Cookie | Purpose |
|---|---|
| `__Secure-access-token` | JWT — used for all API/GQL calls (HttpOnly) |
| `__Secure-whatnot-live` | Phoenix token — WS auth via `sessionExtensionToken` URL param |
| `__Secure-refresh-token` | `wn_rt_` prefixed refresh token (HttpOnly) |

**WS connect URL**: `wss://www.whatnot.com/services/live/socket/websocket?_csrf_token={csrf}&client_layer=nextjs&client_type=web&client_version=20260907-2019&sessionExtensionToken={token}&vsn=2.0.0`

Session token endpoint: `GET /services/live/socket/v3/session` → `{csrf_token, session_extension_token}`
(tokens expire ~5 min; must call from within browser context due to Cloudflare WAF)

## GraphQL notes

- Endpoint: `POST https://www.whatnot.com/services/graphql/?operationName={name}&ssr=0`
- Introspection: disabled
- Global ID formats used: `UserNode:{id}` (base64) for private ops; `PublicUserNode:{id}` for public profile ops
- `getUser(id: PublicUserNode:{id})` returns `PublicUserNode` type — no private fields in schema

## WS Phoenix channels

| Topic | Socket | Access |
|---|---|---|
| `general:{user_id}` | live | Private — 403 for non-owner |
| `chat:{stream_uuid}` | live | Public |
| `auction:{stream_uuid}` | live | Public |
| `commerce:{stream_uuid}` | auction | Private to buyers in stream |

## Findings

### WS-1: No IDOR in Phoenix channels [Closed — not a finding]
`general:{userId}` returns `phx_reply` with `status: "error", response: {reason: "unauthorized"}` when
a user attempts to join another user's private channel. Properly enforced at server level.

### WS-2: Seller channels gated [Closed — not a finding]
Seller-specific channels (e.g., seller commerce view) return 403 for non-seller sessions.

### WS-3: `user_joined` events are per-user, not broadcast [Closed — not a finding]
`user_joined` events on `chat:{stream_uuid}` are sent only to the joining user about themselves,
not broadcast to all subscribers. Dual-session test confirmed no cross-user event leakage.

### WS-4 (Minor — Low/Info): `user_joined` payload exposes viewer device fingerprint
**Status**: Potential Low / Informational  
**Affected endpoint**: `chat:{stream_uuid}` channel, `user_joined` event  
**Description**: The `user_joined` event payload (sent to the joining viewer on their own join)
contains a `pinnedProduct.highestBid.userAgent` field, e.g.:
```
"Whatnot v26.37.0, Android 16, Samsung SM-S928B"
```
This reveals the **highest bidder's** device type, OS version, and device model to every new viewer
who joins the stream (since `pinnedProduct` is included in the initial state on join).
This is a one-way info disclosure: any viewer learns another user's device fingerprint.  
**Impact**: Low — device model/OS version of a buyer is disclosed to other viewers.
**Note**: `rtmpUrl` field is null (not exposed).

### GQL-1: `GetAccountStandingOverview` — cross-user rejected [Closed — not a finding]
Substituting User B's `UserNode` global ID (`VXNlck5vZGU6NzE5Mzg4NjI=`) returns:
`"Viewer unauthorized - "` — server-side auth check on userId param.

### GQL-2: `getUser(id)` returns public-only type [Closed — not a finding]
`getUser(id: PublicUserNode:{id})` returns `PublicUserNode` type. Fields like `email`,
`phoneNumber`, `address`, `totalSales` are not on this type — schema-gated.

### REST: `api.whatnot.com` — not testable
`api.whatnot.com` is not accessible from the `www.whatnot.com` browser context (CORS).
Cookies are scoped to `www.whatnot.com` and not sent cross-domain. Would require:
- Bash/curl with extracted access token (HttpOnly — not extractable via JS)
- A second browser profile logged in as User B with ability to make cross-site requests

## Two-account GQL IDOR results (completed 2026-09-08)

User B fresh JWT obtained. GraphQL tested with `Authorization: Bearer {token}` + `credentials: omit`.
This bypasses cookie jar entirely and authenticates as User B.

| Test | Result |
|---|---|
| B→A `GetAccountStandingOverview(userId=A)` | "Viewer unauthorized" — ✓ protected |
| B→A `node(id: UserNode:A)` relay interface | Returns `null` — ✓ protected |
| B→A `getUser(id: UserNode:A)` | Coerces to `PublicUserNode`, schema blocks `email`/`inbox` — ✓ protected |
| B→A `getUser(id: PublicUserNode:A).purchases` | `Cannot query field 'purchases' on PublicUserNode` — ✓ schema-gated |
| B→A `getUser(id: PublicUserNode:A).loyaltyProgram.myUnlockedRewards` | `currentProgram: null` (no active program) — no sensitive data |
| `me{}` as User B: `paymentMethods`, `shippingAddresses`, `dateJoined` | Not on `UserNode` type — schema-gated |
| WS `general:71938723` as User B | Cannot obtain User B `session_extension_token` without cookie session; WS IDOR already confirmed as protected via User A testing |

REST `api.whatnot.com`: All REST paths return 404 — the REST API surface is not exposed at standard paths. Possibly mobile-only or internal.

## Engagement summary

**Status: No reportable IDOR found**

All tested vectors are properly access-controlled:
- Phoenix WS channels: owner-only enforcement at server level
- GraphQL user-scoped operations: server-side "Viewer unauthorized" checks
- GraphQL schema design: `PublicUserNode` vs `UserNode` split prevents private field exposure via cross-user queries
- Relay `node(id)` interface: returns null for other users' private node IDs

**WS-4** (userAgent disclosure) is the only candidate, but it is very minor:
- The bidder's device string is in `pinnedProduct.highestBid.userAgent` in the `user_joined` event
- Visible only to the joining viewer (not broadcast to all)
- Device model/OS only — no PII
- Likely Informational/N/A on HackerOne

## Next steps

1. **WS-4 decision**: Decide whether to report the `userAgent` disclosure as Informational.
   The finding is: joining viewer receives highest bidder's device fingerprint in the
   `user_joined` → `pinnedProduct.highestBid.userAgent` field. Low/Info severity.
2. **Expand scope**: Test seller-specific flows (listing creation, order management) which
   require an active seller account. Neither test account is a seller.
3. **eToro engagement**: Switch to `gmaxresonance@bugcrowdninja.com` Bugcrowd engagement.

## Payout table

| Severity | Bounty |
|---|---|
| Low | $300 |
| Medium | $1,000 |
| High | $5,000 |
| Critical | $10,000 |
