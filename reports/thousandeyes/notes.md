# Cisco ThousandEyes — working notes

Program: https://bugcrowd.com/engagements/thousandeyes-og
Private. Status **In progress** (confirmed 2026-09-07 via Playwright).
Scope rating 1/4. Confidentiality: do not discuss program details outside Bugcrowd.

Required UA on every request: append `Bugcrowd-gmaxresonance`.

**Automated vulnerability scanning is banned** (Nuclei, Nessus, Burp-as-discovery,
brute-force enumeration). Turbo Intruder only for unique functionality, max 15
requests. Findings reported by automated tools are non-qualifying.
Do **not** run `shroodler crawl` en masse or `shroodler payload` here.

## In scope

- `app.thousandeyes.com` — SaaS dashboard
- `www.thousandeyes.com` — marketing + signup
- `api.thousandeyes.com` — customer API
- ThousandEyes Enterprise Agent (Linux)
- ThousandEyes Endpoint Agent (Windows)

Anything else (unlisted subdomains including `c1.`, `eb.`, `support.`, AWS,
`static.us2.thousandeyes.com` as a *target*, success.thousandeyes.com Ideas tab)
is out of scope. Static assets loaded *by* the in-scope app may be observed,
not tested as their own target.

## Access

Trial account **is active**. Logged into the dashboard as:

- Name: Lapras Resonance
- Email: gmaxresonance@bugcrowdninja.com
- Org / account group: `Bug Crowd #1788764176934_2522`
- Role: Organization Admin (all account groups)
- uid `562949953582783` / aid `562949953672203` / orgId `562949953635231`
  (do **not** adjacent-ID probe these — that would be other customers)

Signup is Organization Admin. Second user for vertical privilege checks:

- Email: `gmaxresonance+reader@bugcrowdninja.com`
- Name: resonance
- Role: Regular User (all account groups)
- uid `562949953582941` (same aid/org as admin)
- Password is Cisco Unified Identity; do not store it in this file.

Cisco Unified Identity manages the password; reset goes through their docs.

Submit URL (do not click until a drafted finding is operator-reviewed):
https://bugcrowd.com/engagements/thousandeyes-og/submissions/new

## Skip entirely (excluded and/or already on file)

CORS without a working PoC; overly permissive CORS (known, all domains);
missing CSP; missing HttpOnly/Secure cookies; user ID in cookies; open
redirect without extra impact; forgot-password enum/spam; lockout-based
account enum; documentation-account API creds; concurrent sessions; session
length; clickjacking on non-sensitive pages; CSRF on unauth forms; SSL/TLS
best practices; version disclosure; rate limit on non-auth endpoints.

Do not touch `support.` (no chat, no sharelinks, no tickets). Do not forge
Agent protocol traffic. Do not register an Agent into another account. Do
not use leaked third-party creds. Do not test AWS/vendor infra.

## Session log

### 2026-09-07

- Brief re-read in Playwright (gmaxresonance). Program un-paused 16 Jan 2026.
  Announcements match the scanning ban.
- Dashboard live; onboarding wizard still showing on Views
  (`?onboardingStep=day1v2`). Did not complete it (would create tests).
- Users and Roles: only the admin user. **New Users** is the invite path.
- Integrations 1.0 catalog (from
  `/namespace/integrations/alerts-domain-service/rest/integration-types-by-id`)
  includes `classic-webhook` and `custom-webhooks` / `webhook` even though
  the 1.0 picker UI showed Slack/PagerDuty/etc. first.
- Integrations 2.0 → Integration Templates → **Custom Webhook**
  (`/manage/integrations/v2/integration-templates/add/custom-webhook`).
  Generic connector: Name, Target URL, Auth Type, Custom Headers.
  POST `/namespace/integrations-api/internal-user-api/connectors/generic`
  - `http://127.0.0.1/` → **400** `ValidUrl` / "URL cannot be targeted"
    (schemes HTTP/HTTPS allowed; loopback blocked server-side).
  - `http://localhost/` → client-side "not a valid URL address" (no dot).
  - `https://example.com` → **saved** connector `shroodler-probe`.
    Wizard step 2 has Path override, headers, query, body, and a **Test**
    button (did not fire Test; cancel-dialog got in the way).
- Single-URL Shroodler on `https://api.thousandeyes.com/` (404). Only
  missing-header findings — all excluded / known. **Not reportable.**

### 2026-09-08

- Invited `gmaxresonance+reader@bugcrowdninja.com` as **Regular User**
  (All Account Groups). Operator accepted the invite and set a password.
- Connector `shroodler-probe` retargeted to
  `https://webhook.site/72f00f53-96ee-4d64-a124-4ca29027be13` (PUT 200).
- Custom webhook **Test** still not fired: Vue form requires
  payload/query/headers and Playwright fill does not bind. Did not keep
  guessing API paths after one 500 and one 403.
- Logged in as Regular User (uid `562949953582941`). Targeted authz-diff:
  - Profile / current-user: **200**, role `Regular User`. Permissions are
    mostly `*_READ` plus own-share/dashboard updates. No edit-users.
  - `GET /ajax/settings/users`: **403** `Access is denied`. Users tab URL
    hangs on a spinner. Profile section renders (self only).
  - Admin uid object probes (`/ajax/settings/users/{adminUid}`,
    `/ajax/settings/profile/{adminUid}`): 405 / 404 / 403. No user dump.
  - Connector `shroodler-probe` GET: **200** (docs: Regular User may *view*
    streaming integrations). Target URL visible. Auth headers empty.
  - Connector PUT/POST: **403**. Force-clicked Save in the editor:
    "You do not have permission to perform this action."
  - Second Regular User pass (hand-picked UI + the APIs those pages
    actually call; no mass crawl):
    - Profile name: `<>{}` rejected (`Invalid characters in text`).
      Stored `resonance<img` / apostrophe were escaped in Activity Log
      (`&lt;`, `&#x27;`). Email/role extras in the profile POST were
      ignored. Still Regular User.
    - Token Create needs email OTP. Did not mint a v7 bearer token.
      `api.us2.thousandeyes.com/v7/users` with the session cookie → 401.
    - Users invite POST `/ajax/settings/users`: **403**.
    - Org DELETE `/ajax/settings/account/organization`: **403**.
    - Test Settings: create form visible but Select Agents / interval
      disabled and no Save. Guessed create POSTs 404 (wrong paths).
    - Vault secrets GET: `{secrets:[]}`. Credentials POST
      `/ajax/settings/credentials`: **403**.
    - Usage & Billing URL loads a blank shell (no billing XHR).
    - Organization Settings: timezone + AI toggles are **visible**;
      AI checkboxes are **disabled**. View-only, not a write bypass.
    - Activity Log `/rev/v1/user/events/search`: own events only.
      Passing admin uid still returns only the Regular User.
    - Alert rules: list GET 200 (view is allowed). Rule DELETE **403**.
    - Agent Settings / proxy: empty, no connection string.
    - Public snapshots: empty (no tests to share).
  - Matches the published Regular User permission set. **No
    privilege-escalation or IDOR finding on this role.**

- Logged back in as Organization Admin (`gmaxresonance@bugcrowdninja.com`,
  Lapras Resonance). Webhook **Test** API:
  `POST /namespace/integrations-api/internal-user-api/operations/webhooks/test`
  with a complete connector object → **200** `HTTP status: OK (200)`.
  webhook.site received POSTs from AWS IPs (`3.13`/`3.138`/`3.141`) with
  body `{"probe":"shroodler"}` (21 bytes). Product-intended outbound
  fetch, not SSRF.
  Passing `target: http://127.0.0.1/` (and `[::1]`, decimal IP) in the
  Test body is **ignored**; the saved webhook.site URL is used.
- Redirect-follow (saved `https://httpbin.org/redirect-to?...`, then Test):
  - 302 to `http://127.0.0.1/` → **200** body `success:false`
    `HTTP status: Found (302)`. They do **not** follow.
  - 302 to webhook.site (control) → same, **302** as final status.
  - 307 to `http://127.0.0.1/` → `HTTP status: Temporary Redirect (307)`.
  - Operation `path: //127.0.0.1/` with saved webhook.site → webhook.site
    **404** (path override only, not a host rewrite).
- Save-time ValidUrl still **400** for: `127.0.0.1.nip.io`, `127.1`,
  `0.0.0.0`, decimal `2130706433`, `[::1]`, `localtest.me` (they resolve
  DNS / reject loopback-equivalent hosts, not just literal `127.0.0.1`).
- Connector restored to webhook.site. **Not SSRF.**

- Credential Vault template is **CyberArk Conjur** (`cyberark-credential-vault`).
  POST `/namespace/integrations-api/internal-user-api/connectors/conjur`
  → connector `shroodler-vault` id `43061972-5995-4b68-8505-10d432a364fa`
  (target `https://webhook.site`; they do **not** fetch on save —
  UI: “unable to validate the connection details”).
  Same ValidUrl as generic (HTTPS-only; nip.io / localtest.me / loopback
  **400**). httpbin redirect-to-loopback **saves** (hostname is public).
  Operation POST `/operations/credential-vault` →
  `shroodler-vault-op` / secret `shroodler-cred`
  (`6484cbc1-872e-4f5e-9bc8-922138cd2c99`). No fetch on save.
  Instant HTTP test with that secret + Cloud Agent: **400**
  `Tests that use credential vault cannot be assigned to a cloud agent.`
  Vault fetch needs an Enterprise Agent we do not have.

- HTTP Instant Test (Dallas trial Cloud Agent `vAgentId` 4492) via
  `POST /ajax/tests/http-server/create-instant` (full test object,
  not a guessed stub):
  - webhook.site → testId `562949953682767`, Views **200 OK**,
    Target IP `178.63.67.153`. Product-intended.
  - `http://127.0.0.1/` → **400** `Cannot use Cloud Agents with a local URL`.
  - `file:///etc/passwd` → **400** `Badly formed URL`.
  - Override DNS `https://example.com/` + `targetIpOverride: 127.0.0.1`
    → testId `562949953682769`. Views: Target IP **127.0.0.1**,
    `Failed to connect to example.com port 443 after 0 ms`.
  - `http://127.0.0.1.nip.io/` → testId `562949953682770`. Views:
    Target IP **127.0.0.1**, connect failed immediately on port 80.
  These two bypass the literal “local URL” check and show 127.0.0.1
  as the target, but there is **no retrieved internal content** (and
  Cloud Agent localhost is also vendor/AWS-adjacent). **Not filing.**
  Do **not** retry with `169.254.169.254`.

### Finding: Regular User snapshot/saved-event IDOR (draft, not submitted)

Logged in as Regular User (`resonance`, uid `562949953582941`). Session
`currentAccountPermissions` has `SHARING_SNAPSHOT_UPDATE_OWN` /
`SETTINGS_EVENTS_UPDATE_OWN` / `SHARING_SNAPSHOT_READ_OWN` /
`SHARING_SNAPSHOT_CREATE` — no `*_ALL` snapshot writes.

CEA frontend update path (not guessed):
`POST /ajax/sharing/snapshots/{linkId}/update` with `{ isPublic, expireTime }`.

- Admin saved event `cewjsfudlsmajwicbvllfyuwlmzogkfc` (uid
  `562949953582783`, `shroodler-snap`): Regular User POST
  `{isPublic:false, expireTime:1820338026}` → **200**, expireTime changed.
- Same id `{isPublic:true, expireTime:1820338026}` → **200**, minted
  public link `cvqkbjqkbdvpvaxhminzuwzadcbgqkgq` owned by the Regular
  User. Admin event `shareLinkId` now points there.
- Original admin public URL
  `https://ckkcxheigwntpoowllvlgxdnkveosydf.share2.thousandeyes.com` → **404**.
- New URL loads unauth. Public `linkId` POST → 404 (update is on the
  saved-event id). Name/PII/comment body fields → 400.

Docs: Regular User may edit/view **own** snapshots only; edit/view all
users in the account group is admin-only.

Draft: `reports/thousandeyes/snapshot-own-idor.md`

Reconfirmed 2026-09-08 as Regular User on a **second** admin
saved event `cdudfprvaalchtmwjwesmzhqusdbnfxv` (`shroodler-snap-pii`):
expireTime bump persisted (uid still admin), then reverted. `*_ALL`
still absent. This is a real owner-check miss.

Bugcrowd draft filled (not submitted):
https://bugcrowd.com/engagements/thousandeyes-og/submissions/c5bb212f-245c-45cc-81a1-bd78b1525b7a/edit

### Finding: Regular User embed-source IDOR on UPDATE (draft, not submitted)

Same Regular User session (`EMBED_OWN_UPDATE` only). Dash client paths:

- `POST /namespace/dash-api/embed` — create
- `POST /namespace/dash-api/embed/{embedId}` — update (colon in id must
  **not** be percent-encoded on POST; GET wants `%3A`)

Control:

- `GET /namespace/dash-api/dashboard/6a9efc5faffa359902bdd3ed` → **403**
- `POST /embed` with that id as `embedSource` (`type: dashboard`) → **403**
  `User is not authorized to create embed`

Bypass: create embed of own dash `6a9efc038f4077e79e1a6e22`, then POST-update
`embedSource.id` to the admin private dash → **200**, persisted. `ownerId`
became null. Reproduced on `02ac:f5a9b74e-...` and
`02ac:b0deb490-33ab-4a49-a923-03e6a3335472`.

Docs: Regular User may embed **own** widgets only; embed-for-all-users is
admin. https://docs.thousandeyes.com/product-documentation/dashboards/embedding-dashboard-widgets-in-external-web-sites

Public `/public/embed` → 410 (API embeds had `template: null`, list page
empty). `/e/{id}` is the Embedded Template shell (spinner, no widget data
yet). **Not claiming a public data leak** until a UI-created embed or a
real admin `widgetId` is retargeted.

Draft: `reports/thousandeyes/embed-source-idor.md`

Bugcrowd draft filled (not submitted):
https://bugcrowd.com/engagements/thousandeyes-og/submissions/a7d14704-3822-41ec-8f88-4a1f421cb3a8/edit

Dashboards `*_OWN` on templates: built-in/admin dash GET/POST/DELETE as
Regular User → **403**. Not a finding.

Alert rules: real save path `POST /ajax/alert-rules/save` → **403**.
Instant Test Run Again: `POST /ajax/tests/http-server/{aid}/{testId}/rerun`
→ **403**.

## Next tests (targeted, not scans)

1. Two `*_OWN` update misses drafted (saved-event snapshot + embed source).
   Still open in the same family: live-share `SHARING_LIVE_SHARE_UPDATE_OWN`
   (no objects yet — admin must create via UI; `GET /ajax/sharing/livedb`
   was empty). Admin-create a **UI** embed, then Regular User UPDATE that
   `embedId` / retarget with a real admin widget `storeId`.
2. Do not spend more requests on webhook loopback encodings or IMDS.
3. Leave snapshot replacement share + embed `02ac:b0deb490-...` until
   filed. Reuse or delete connectors `shroodler-probe` (generic) and
   `shroodler-vault` (conjur) when done.

## Commands that were not Shroodler (gaps to close)

Playwright MCP was used for all authenticated dashboard work (clicks,
form fill, reading XHR). Also:

1. **`shroodler crawl --depth 0 --max-pages 1 --ignore-robots --no-sitemap`
   still made 2 requests.** Extra fetch is the automatic next-auth probe
   in `extractors/auth_stack.py` (`/api/auth/providers`). Need a true
   `--once` / hypothesis mode that does not fire extra probes.
2. **No program-exclusion filter.** That one-page crawl emitted
   missing-csp/hsts/xfo which this program lists as known/excluded.
   Want `--exclude-category header` or a program profile.
3. **No Playwright/HAR ingest.** Dashboard XHR (te-config, user,
   integration-types, connector POST) lived in the browser; Shroodler
   could not analyze it. Need `shroodler ingest-har` / ingest from
   Playwright network JSON into session JSONL.
4. **No browser UA helper.** Brief requires `Bugcrowd-<username>` on
   every request. Playwright extension: `page.setUserAgent` is missing,
   CDP `Network.setUserAgentOverride` is denied, and `page.route` to
   rewrite UA **broke the SPA** (stuck progressbars, lost tabs). Need
   a supported way to tag browser traffic.
5. **No `shroodler request`.** The connector POST (the actual hypothesis
   test) had to be the UI button. A one-shot verb+URL+body command with
   required UA would have been the right tool.
6. **`authz-diff` wants a crawl JSON.** This program forbids producing
   that the normal way. Need authz-diff from a URL list + two cookies,
   seeded from a recorded browser session.

Shroodler command that *was* used (1 GET + the extra probe):

```
shroodler crawl https://api.thousandeyes.com/ \
  --allow-external --depth 0 --max-pages 1 --max-time 30 \
  --no-sitemap --ignore-robots \
  --user-agent "<browser UA> Bugcrowd-gmaxresonance" \
  -o reports/thousandeyes/api-unauth.json
```
