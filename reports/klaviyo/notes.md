# Klaviyo Managed Bug Bounty

https://bugcrowd.com/engagements/klaviyo-og  
Public, coordinated disclosure, Safe Harbor full, scope 4.  
Rewards: P1 $2100–3500 / P2 $1000–1750 / P3 $450–600 / P4 $150–200.  
VRT 1.19.1. Impact governs over baseline. BAC without attacker benefit is Informational.

## Rules that matter

- Sign up with a Bugcrowd email. Company name must include `Bugcrowd`
  (e.g. `Klaviyo-Bugcrowd`).
- Own/authorized accounts only. **Attacking customer accounts is prohibited.**
- Do not enumerate `/api/v1/people` (single GET of the base path / `page=1` only).
- Do not target Microsoft `20.*` public space.
- No automated form spam. No mass crawl / payload blast.
- Stored XSS only if it hits other accounts or email recipients.
- Premium/paid features are invitation-only; do not email for access.
- Identify test traffic with UA suffix `Bugcrowd-gmaxresonance`.

## In-scope web/API (use these; skip office/VPN IPs for now)

| Target | Notes |
|---|---|
| `https://klaviyo.com/*` | Django web app |
| `https://a.klaviyo.com/api/*` | Customer API — [docs](https://developers.klaviyo.com/en/) |
| `https://*.myklpages.com/*` | Hosted landing pages |
| `https://*.services.klaviyo.com` | Services |
| `https://*.klaviyomsv.com/*` | MSV |
| `https://*.klaviyo-dev.com/*` | Dev |
| `http://mcp.klaviyo.com/` | MCP |
| `https://*.clovesoftware.com` | App (legacy?) |
| `https://*.clovesoftware-dev.com` | Dev |
| Klaviyo AWS/S3 assets | Misconfig only if we land on a real bucket |

Docs: https://help.klaviyo.com/hc/en-us

## Hunt

Two free accounts, then same-session IDOR: create list/profile/campaign/share
as A, replay update/delete/share/API as B. Brief explicitly flags **Email Open
Tracking Consent** as an IDOR focus.

Do not submit reports unless asked.

## Accounts

- A: `gmaxresonance+klaviyo-a@bugcrowdninja.com` — company `Klaviyo-Bugcrowd-A`
  (account created; onboarding through sender-info done; sitting on
  `/email-confirmation`. Confirm subject: `Confirm your Klaviyo email`
  from `no-reply@klaviyo.com`. Password not stored here.)
- B: `gmaxresonance+klaviyo-b@bugcrowdninja.com` — company `Klaviyo-Bugcrowd-B` (not created yet)
