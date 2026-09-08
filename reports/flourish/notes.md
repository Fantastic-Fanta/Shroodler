# Flourish

https://bugcrowd.com/engagements/flourish  
Public. Validation within **3 days**. Scope 3. Avg payout $350 (last 3 months).  
Flat rewards: P1 $6000 / P2 $2500 / P3 $850 / P4 $100.  
Canva-owned (brief still says Canva in one OOS line). Product is flourish.studio.

## Rules

- **Must** use `@bugcrowdninja.com` for all testing.
- Tag attack traffic with header `X-BugBounty: gmaxresonance`.
- Include a bug URL in any submission or it will not be accepted.
- Own accounts only. Do not access other users’ data.
- ID enumeration (user/design/folder) without further impact is OOS.
- Rate-limit bypass OOS unless it bypasses OTP.
- CSRF in components is P4 unless ATO is shown.
- XSS on `templates.flourish.studio`, `preview.flourish.studio`,
  `demos.flourish.studio`, `flo.uri.sh` is known — only report with
  escalated impact, not a second alert box. Custom-template XSS that
  you could do by uploading a template is rejected.
- Untrusted-content hosts (`flo.uri.sh`, flourish-user-templates.com,
  flourish-user-preview.com): simple XSS / open redirect not paid.
- `training.flourish.studio` is out of scope.
- Do not verify leaked credentials/cookies/keys — report and stop.
- Identify test traffic with UA suffix `Bugcrowd-gmaxresonance`.

## In scope

- `https://flo.uri.sh`
- `*.flourish.studio` (https://flourish.studio/)
- `*.xyzbmojn.net`
- flourish-user-templates.com
- flourish-user-preview.com
- `*.kiln.it`

Focus: main flourish.studio app + `*.xyzbmojn.net`.

## Hunt

Two accounts. Create a private visualization/project as A, then as B try
read/edit/delete/share/unshare that known id. Demonstrated impact, not enum.

Do not submit reports unless asked.

Vuln drafts go in `reports/flourish/`. Non-Shroodler command log:
`docs/flourish-hunt-commands.md`.

## Accounts

| | Email | Username | Notes |
|---|---|---|---|
| A | `gmaxresonance@bugcrowdninja.com` | `gmaxresonance` | user_id `3676151`. Email verified (settings ✅). Brave. Free plan. |
| B | `gmaxresonance+2@bugcrowdninja.com` | `gmaxresonance2` | Email verified. Cursor IDE browser. Empty projects. Intended `+flourish-b` / `gmaxres_flob` was not the account Flourish created. |

Passwords are not stored here.

## Known objects (A, unpublished)

- Viz `30181860` named `bc-idor-a`
- Data table `46226049`
- Story `3810739`
- Folder `816628` (`bc-share-a`)
- Preview: capability URL on `flourish-user-preview.com` (not IDOR)

## Closeout

See `reports/flourish/NO-P2-CLOSEOUT.md`. No P2+ draft. Command log:
`docs/flourish-hunt-commands.md`.

Peer-write as B (after valid CSRF + body) is `ACL_PERMISSION_DENIED`
on viz/table/story/folder/publish/admin. Validate-first 400s are not
findings. Remaining untested: company/SAML/webhooks/MCP, Canva OAuth,
xyzbmojn tenants, password-reset entropy.
