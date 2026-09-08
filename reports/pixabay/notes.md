# Pixabay

https://bugcrowd.com/engagements/pixabay  
Public. Validation within **1 day**. Scope 1. Avg payout $100 (mostly P4).  
Flat rewards: P1 $6000 / P2 $2500 / P3 $850 / P4 $100.  
Canva-owned; brief still says “Canva” in a few places.

## Rules

- **Must** use `@bugcrowdninja.com` for all testing (announcement 2021; still mandatory).
- Own accounts only. Do not access other users’ data.
- No noisy scanners. **Max 1 request/second.**
- ID enumeration (user/design/folder) without further impact is out of scope.
- Rate-limit bypass OOS unless it bypasses OTP.
- Free low-quality content without paying is OOS; paid-quality bypass is in scope.
- Do not verify leaked credentials/cookies/keys — report and stop.
- No DoS, phishing, physical, version-only, non-sensitive cookie flags.
- Third-party generic (Zendesk, Mandrill, Pagely) is meh; AWS/Cloudflare misconfig they want.
- Identify test traffic with UA suffix `Bugcrowd-gmaxresonance`.

## In scope

- `https://pixabay.com/` and `*.pixabay.com/`

## Hunt

Two accounts, then IDOR with demonstrated impact (edit/delete/leak), not enum.
Collections, follows, DMs, upload replace, API tokens, paid-quality download.

Do not submit reports unless asked.

## Accounts

- A: `gmaxresonance@bugcrowdninja.com` — username `u_2zg54emgv7`, uid `57502065`
  Profile: `/users/u_2zg54emgv7-57502065/`
  Private collection `bc-idor-a` id `34023606`
  (`/accounts/collections/34023606/`). Password not stored here.
- B: `gmaxresonance+pixabay-b@bugcrowdninja.com` — username `gmaxres_pixb`, uid `57502143`
  Profile: `/users/gmaxres_pixb-57502143/`
  Private collection `bc-idor-b-renamed` id `34023659`
  Also auto collection `Saved` id `34023657`. Password not stored here.
  Playwright Join is blocked (`Please do not use automatic tools`); operator typed Join.

## IDOR so far (as B vs A) — no write impact yet

Denied (404/403):
- GET `/accounts/collections/34023606/` (A private) → 404
- GET `/collections/bc-idor-a-34023606/` → 403 Access denied
- POST add/remove/edit/delete/reorder on `34023606` → 404
- Staff `/xmin/accounts/login_as/u_2zg54emgv7/` → 401 Cloudflare
- Newsletter subscribe POST on A's uid → 403
- change_email / change_password forms are session-bound (no user/pk field)

Intended / weak:
- Follow A, list `/accounts/followers/57502065/` (public social graph)
- POST like A's private collection → `{"liked": true}` but contents still 403/404
- DMs: compose is `/accounts/messages/compose/{userId}/` with empty hidden `pk`; recaptcha required, not sent yet

## A session (2026-09-08)

- Logged in as `u_2zg54emgv7` / `57502065`.
- API keys are `{uid}-{25 hex}`. Hex is not md5/sha1/sha256 of uid or email. Uid-only key is rejected. Do not store keys here.
- Uploaded test photo id **`10464573`** via `/accounts/media/fileuploader/` (min 3000px long side). Saved with `/accounts/media/save_unsubmitted/photo/10464573/` JSON → `{"success": true}`. Shows as **draft** (`draftCount: 1`), not published.
- Comment create is captcha-gated; do not retry create spam (hit CF 1015/429). Cool down.

## B session in Cursor browser (2026-09-08)

Two cookies at once: Brave = A, Cursor browser = B (`gmaxres_pixb` / `57502143`).

As B vs A's draft `10464573`:
- POST save_unsubmitted → **404**
- POST delete/photo → **200** `{"success": false}`
- POST tags/edit → **200** `{"reload": true, "tags": [], "description": ""}` — same body for fake id `1`. Not an IDOR.
- GET `/photos/10464573/` → generic shell, no draft leak
- A still has `draftCount: 1` and can save the draft

No write impact. Collections already denied. Next surfaces if we stay: forum, playlists, or park.
