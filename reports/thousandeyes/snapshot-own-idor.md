# Regular User can update other users' saved events and replace their public snapshot URLs

**Program:** Cisco ThousandEyes Vulnerability Hunting (Bugcrowd, `thousandeyes-og`)
**Target:** `app.thousandeyes.com` (in scope)
**Class:** Broken object-level authorization / vertical privilege (CWE-639, CWE-285)
**Suggested VRT:** Privilege Escalation / Insecure Direct Object Reference
**Suggested severity:** P3 (same-org). Regular User permissions are `*_OWN` only; the
write lands on another user's object and can take down that user's existing
unlisted public share URL.
**Do not submit until operator review.** Submit URL:
https://bugcrowd.com/engagements/thousandeyes-og/submissions/new

Tester: gmaxresonance. Required UA suffix `Bugcrowd-gmaxresonance` was used.
All objects are in the tester's own trial org (`Bug Crowd #1788764176934_2522`).
No adjacent-org IDs were probed.

## Summary

A built-in **Regular User** is granted only:

- `SETTINGS_EVENTS_UPDATE_OWN`
- `SHARING_SNAPSHOT_UPDATE_OWN`
- `SHARING_SNAPSHOT_READ_OWN`
- `SHARING_SNAPSHOT_CREATE`

and is **not** granted `SHARING_SNAPSHOT_UPDATE_ALL` / `SHARING_SNAPSHOT_READ_ALL`.

Published role docs match that split:

- Regular User: "Edit own private snapshots", "Edit own public snapshots",
  "View own snapshots"
- Organization / Account Admin only: "Edit own private snapshots for all users
  in account group", "Edit public snapshots shared by all users in account
  group", "View snapshots shared by all users in account group"

  https://docs.thousandeyes.com/product-documentation/user-management/authorization/rb-access-control/built-in-roles-and-permissions

`POST /ajax/sharing/snapshots/{linkId}/update` does **not** enforce the owner
check. Logged in as Regular User `resonance`
(`gmaxresonance+reader@bugcrowdninja.com`, uid `562949953582941`), the same
request that the CEA frontend uses to update a snapshot accepted an
Organization Admin's saved-event `linkId` (uid `562949953582783`,
`Lapras Resonance`) and returned **200**.

Two writes were confirmed:

1. **Mutate the admin object.** `{ isPublic: false, expireTime: 1820338026 }`
   changed the admin saved event's `expireTime` from `1820337966` to
   `1820338026`. `uid` / `creatorName` stayed the admin's.
2. **Republish and replace the public URL.** `{ isPublic: true, expireTime: 1820338026 }`
   minted a new unlisted public snapshot owned by the Regular User and
   **repointed** the admin saved event's `shareLinkId` to it. The admin's
   previous public URL then **404s**.

Regular Users are allowed to create *their own* snapshots of tests they can
view (`SHARING_SNAPSHOT_CREATE`). That is not this bug. The bug is updating
**another user's** saved-event `linkId` and destroying that user's existing
public share.

## Accounts

| Role | Email | uid |
|---|---|---|
| Organization Admin | gmaxresonance@bugcrowdninja.com | 562949953582783 |
| Regular User | gmaxresonance+reader@bugcrowdninja.com | 562949953582941 |

Account group aid `562949953672203` / orgId `562949953635231`.

## Steps to reproduce

1. As Organization Admin, create a saved event / public snapshot of any test
   (UI: Views → Snapshot). Note the **saved-event** `linkId` (not the public
   `share2` hostname). Example object used here:

   - Saved event `linkId`: `cewjsfudlsmajwicbvllfyuwlmzogkfc`
   - Owner uid: `562949953582783`
   - Original public URL:
     `https://ckkcxheigwntpoowllvlgxdnkveosydf.share2.thousandeyes.com`
   - Original `expireTime`: `1820337966`

2. Log out. Log in as a built-in Regular User in the same account group.

3. Confirm the session really is Regular User (from `teConfig.currentSessionUser`):

   - `currentAccountPermissions` includes `SHARING_SNAPSHOT_UPDATE_OWN` and
     `SETTINGS_EVENTS_UPDATE_OWN`
   - It does **not** include `SHARING_SNAPSHOT_UPDATE_ALL` or
     `SHARING_SNAPSHOT_READ_ALL`

4. List saved events (Regular User has `SETTINGS_EVENTS_READ`; this call
   also returned other users' events and their unlisted public URLs):

   ```
   GET /ajax/sharing/snapshots?isPublic=false&dataKinds=AGENT
   Cookie: <Regular User session>
   ```

5. Send the same update the frontend uses
   (`/tmp/te-cea-fe.js` → `POST /ajax/sharing/snapshots/${linkId}/update`
   with `{ isPublic, expireTime }`), targeting the **admin** saved-event id.
   Include the page CSRF token:

   ```
   POST /ajax/sharing/snapshots/cewjsfudlsmajwicbvllfyuwlmzogkfc/update
   Content-Type: application/json
   X-CSRF-Token: <meta name=csrf-token>
   Cookie: <Regular User session>

   {"isPublic":false,"expireTime":1820338026}
   ```

   Response: **200**. Body still has `uid: 562949953582783`,
   `creatorName: "Lapras Resonance"`, `publicLinkType: "SAVED_EVENT"`,
   `expireTime: 1820338026`.

6. Republish that same admin object:

   ```
   POST /ajax/sharing/snapshots/cewjsfudlsmajwicbvllfyuwlmzogkfc/update
   Content-Type: application/json
   X-CSRF-Token: <meta name=csrf-token>
   Cookie: <Regular User session>

   {"isPublic":true,"expireTime":1820338026}
   ```

   Response: **200**. New fields on the admin saved event:

   - `shareLinkId`: `cvqkbjqkbdvpvaxhminzuwzadcbgqkgq`
   - `sharedPublicLink`:
     `https://cvqkbjqkbdvpvaxhminzuwzadcbgqkgq.share2.thousandeyes.com`

   The public-snapshot list then shows that new link as owned by the
   Regular User (`uid: 562949953582941`, `creatorName: "resonance"`).

7. Open both public URLs unauthenticated:

   - New URL loads the snapshot (test `shroodler-instant`, 200 OK from
     Dallas trial agent). `teConfig.isPublicLink === true`.
   - Original admin URL
     `https://ckkcxheigwntpoowllvlgxdnkveosydf.share2.thousandeyes.com/...`
     now returns **Page Not Found** (HTTP 404).

Control: the same POST against the Regular User's own saved-event
`czkemkyteotuzbeygsvjgfqmrjqyjrhv` also returns 200 (expected, `*_OWN`).
POSTing the **public** `linkId` (`ckkcxheigwntpoowllvlgxdnkveosydf`) returns
404 — the broken check is on the saved-event id, which is what the UI
update path uses.

Name / PII / comment-flag fields in the body are rejected with 400. The
accepted fields are `isPublic` and `expireTime`.

## Impact

A Regular User in the account group can:

- Change the expiration of another user's saved event.
- Publish that event to a new unlisted `*.share2.thousandeyes.com` URL
  under the Regular User's name.
- **Invalidate the owner's existing public share URL** (404). Anyone the
  owner already sent that link to loses access.

That is admin-only snapshot edit behavior. Public snapshot URLs are
unlisted capability-URLs; replacing one is both an integrity failure for
the owner and a new external disclosure of the same test data on a URL
the owner did not create.

Same-org only. Not cross-tenant. Regular User can already snapshot tests
they can view; the extra impact is operating on **someone else's**
saved-event object and killing that person's share link.

## Evidence (this session)

| Actor | Request | Result |
|---|---|---|
| Regular User | POST update admin saved event `cewjsfudlsmajwicbvllfyuwlmzogkfc` `{isPublic:false, expireTime:1820338026}` | 200, expireTime changed, uid still admin |
| Regular User | POST same id `{isPublic:true, expireTime:1820338026}` | 200, new public link `cvqkbjqkbdvpvaxhminzuwzadcbgqkgq` owned by Regular User |
| Unauth | GET original public URL `ckkcxheigwntpoowllvlgxdnkveosydf.share2...` | **404** |
| Unauth | GET new public URL `cvqkbjqkbdvpvaxhminzuwzadcbgqkgq.share2...` | snapshot renders |

## What this is not

- Not a guessed path. Endpoint is in the CEA frontend
  (`POST /ajax/sharing/snapshots/${id}/update`).
- Not CSRF-as-the-bug (CSRF on non-sensitive forms is excluded). The
  request was made with a valid Regular User session + CSRF token.
- Not "Regular User can create snapshots" — that permission is
  intentional. The missing check is owner-on-update.

## Cleanup left in the org

- Replacement public snapshot:
  `https://cvqkbjqkbdvpvaxhminzuwzadcbgqkgq.share2.thousandeyes.com`
- Admin saved event `cewjsfudlsmajwicbvllfyuwlmzogkfc` now points at that
  link; original `ckkcxheigwntpoowllvlgxdnkveosydf` is dead.
- Leave these until the report is filed so triage can replay.
