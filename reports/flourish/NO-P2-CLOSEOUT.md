# Flourish — no P2+ draft (closeout)

**Program:** https://bugcrowd.com/engagements/flourish  
**Tester:** gmaxresonance  
**Do not submit.** Nothing on the tested free-tier two-account surface
met P2. This file exists so a later review can see what was tried
instead of assuming the hunt never ran.

Suggested VRT if a later session finds a write that actually lands:
Privilege Escalation / IDOR. Payout ladder here is P2 $2500.

## Verdict

No reportable P2 or above. Owner-known unpublished objects stay
unpublished when a second logged-in user (and unauth) hit the same
URLs. After a valid body is supplied, writes return
`ACL_PERMISSION_DENIED` with the same shape as a nonsense id.
Validate-before-ACL `400`s (missing `version_number` / `data` type)
are **not** findings: the versioned/typed replay is denied.

ID strings appearing in 401 messages are existence leaks without
further impact → program OOS.

## Accounts (own only)

| | Email | Username | user_id |
|---|---|---|---|
| A (Brave) | gmaxresonance@bugcrowdninja.com | gmaxresonance | 3676151 |
| B (Cursor) | gmaxresonance+2@bugcrowdninja.com | gmaxresonance2 | (not stored) |

B was *intended* as `+flourish-b` / `gmaxres_flob`. Flourish created
`gmaxresonance2` on `+2` instead. Both emails are now verified.
Passwords are not stored in-repo.

## Known objects (A, unpublished)

- Visualisation `30181860` (`bc-idor-a`)
- Data table `46226049`
- Story `3810739`
- Folder `816628` (`bc-share-a`, `share: true`,
  `shared_with_company_id` null)

Preview URLs on `flourish-user-preview.com/{id}/{secret}` are
capability URLs. Tokened preview was not treated as IDOR. Preview
without the secret is 404.

## What B could not do (ACL 401 unless noted)

Read/edit/delete/duplicate/publish/unpublish/staff-pick/tags/
thumbnail-upload/Canva-embed/PPT-revoke on viz `30181860`.

Read/edit CSV (once `data` is a string) on table `46226049`.
Live CSV is a paid feature (`403` even as A).

Read/edit/delete/duplicate/publish on story `3810739`.

List/nest/delete folder `816628`.

Admin-ish: `POST /api/user/{A}/suspend` → 400 “doesn't belong to a
company”; `reset_mfa` → 403; `change_saml_provider_id` → 403;
`POST /api/user/{A}` role change → 400 no company. User `1` suspend
→ 403 “not a company admin”. Different errors leak company-membership
shape; no action landed.

`company_access` with valid levels `private|viewable|editable` → 401
`update_access`. Invalid levels → 400 (validate-first).

B SDK token (own `GET /api/user/generate_sdk_token`) did not read A's
viz/table via Bearer / Token / X-Api-Key. Revoke returned 500; do not
store the token.

OAuth `/oauth/authorize` requires a known `client_id`; unknown ids
return 400, no open redirect.

Public/unauth: `public.flourish.studio/visualisation/30181860` and
`flo.uri.sh/visualisation/30181860/embed` → 403. Profile
`/@gmaxresonance` → 404 (public profile off).

## Check-order notes (not bugs)

Unverified B hitting `/publish` got “email not verified” **before**
ACL. After B verified, the same call is 401 ACL. Same pattern as
missing-`version_number` DELETE `400` then versioned DELETE `401`.

## Surfaces not finished (why no “absolutely none”)

These can still hide a P2 and were **not** fully tested:

- Company / SAML / webhooks / MCP / review-approve (needs a company
  plan; both accounts are Free).
- Canva Connect OAuth (needs a Canva login).
- `*.xyzbmojn.net` tenants (apex returns empty 200; no tenant name
  in the editor JS).
- `kiln.it` redirects to kiln.digital marketing; no old editor found.
- Password-reset token entropy (`/forgot` exists). Did not log B out
  to mint two reset tokens.
- Email-change token on settings (form not fully exercised).
- Enterprise Live API / API keys (`PUT /api/user/api_keys` is 403
  on Free).

A later session with a company seat or Canva connect should start
there, not by repeating viz GET/POST.

## Shroodler

Peer-write was the right tool. It was not used live because HttpOnly
`flourish` cookies never left the two browsers. See
`docs/flourish-hunt-commands.md`.
