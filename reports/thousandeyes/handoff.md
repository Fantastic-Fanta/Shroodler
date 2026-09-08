# Cisco ThousandEyes — handoff for a new session

Program: https://bugcrowd.com/engagements/thousandeyes-og (private, you
have access). Signed up via https://www.thousandeyes.com/signup with a
`@bugcrowdninja.com` email as of 2026-09-07 -- **account activation
takes up to one business day**, per the brief. If testing attempts are
failing/erroring in a new session, check whether the account is actually
active yet before assuming something's broken.

## The one rule that changes everything about how to approach this

**Automated vulnerability scanning tools are explicitly banned by name**
(Nuclei, Nessus, and "findings reported by automated tools (e.g., Burp
Suite)" are listed as a prohibited/non-qualifying category, not just
discouraged). This is stricter than a generic "no automated scans" line
-- it names Burp Suite itself as unacceptable for how a finding was
*discovered*. **Do not run `shroodler crawl --mode headless` en masse or
`shroodler payload` against this target the normal way.** Every previous
program this session either allowed or didn't explicitly forbid this;
this one does. The two real findings from this session (PulsePoint
cookies, Vienna CORS) were both actually found by single, hand-crafted
curl requests testing one specific hypothesis at a time -- that's the
right model here, not the packs.

Exception carved out explicitly: **Turbo Intruder is permitted, but only
to test unique functionality nothing else can, and capped at 15
requests.** Read as: this program wants targeted, low-volume, manually
reasoned testing, not breadth-first automated fuzzing.

Also required on every request: append `Bugcrowd-<your-bugcrowd-username>`
to the User-Agent string (their own instructions link to how to do this
in Burp/Chrome). Passive/manual curl testing should carry it too.

## Scope

In scope:
- `app.thousandeyes.com` -- the actual SaaS dashboard (tests, alerts,
  reports, agent management)
- `www.thousandeyes.com` -- marketing site + account signup
- `api.thousandeyes.com` -- customer-facing API
- ThousandEyes Enterprise Agent (Linux) and Endpoint Agent (Windows) --
  agent software itself, not just the web surface

**Hard out-of-scope / do-not-touch, several of these are unusual and
easy to trip over by habit:**
- The `support.` subdomain entirely -- no chat, no sharelinks, no
  community interaction, no support tickets. Don't even open a chat
  widget to look at it.
- AWS or any other ThousandEyes vendor's infrastructure -- test
  ThousandEyes, not their cloud provider.
- Manually crafted/altered **Agent traffic** sent to data-ingress or
  controller endpoints (`c1.thousandeyes.com`, `eb.thousandeyes.com`,
  etc.) -- explicitly NOT a valid vector. Vulnerabilities via **Test
  settings configured in the web app** ARE valid, though -- i.e., the
  legitimate path to affect agent behavior is through the dashboard UI,
  not by hand-forging the protocol.
- Registering an Agent into another account, or attempting cross-account
  access beyond your own test accounts.
- Any leaked/third-party credential use.
- Anything from success.thousandeyes.com's "Ideas" tab (new idea,
  comment, upvote, downvote).

**Also explicitly excluded from rewards even if found (skip testing for
these entirely):**
- Missing HttpOnly/Secure cookie flags -- the exact class of finding
  that worked on PulsePoint (Internet Brands program) is a dead end
  here.
- CORS issues **without a working PoC** -- the Vienna CORS finding's
  evidence (header inspection + curl across routes) would NOT be enough
  here; would need to actually demonstrate real cross-origin data theft.
- Missing CSP, missing SSL/TLS best-practices, server version
  disclosure, descriptive error messages -- all the low-hanging
  "missing header"-style findings Shroodler's passive crawl surfaces by
  default are non-starters on this program.
- Open redirect (unless additional security impact demonstrated).
- Username/email enumeration via forgot-password, weak password policy
  reports.
- Rate limiting/brute force on non-auth endpoints.
- Clickjacking without sensitive actions; CSRF on unauthenticated/
  non-sensitive forms.
- Known issues already on file (as of 30 May 2024): user-defined
  hyperlinks in signup welcome emails (assessed low-risk already), and
  documentation-account API credentials being usable for real
  authenticated API requests (already known) -- don't re-report either.

## Focus areas (what they actually want)

IDOR, Authentication Bypass, Auth-related issues, **Local Privilege
Escalation**, **Cross-Account Access**, Incorrect Permissions, Data
Exposure, RCE, SQLi, Command Injection, LFI, RFI, Directory Traversal,
XSS, general OWASP Top 10.

**This is directly relevant to what we discussed about deeper
authenticated testing**: the signup flow makes the account you create an
**Organization Admin**, and the brief explicitly says *"researchers are
encouraged to create other users to test vertical privilege escalation
issues, etc."* -- meaning you can legitimately create a second,
lower-privileged user inside your own org and use Shroodler's
`authz-diff` exactly as designed: crawl authenticated as the admin
account, then `authz-diff --cookie ...` replaying as the lower-priv
account's session, looking for pages/data the lower-priv user shouldn't
reach. This is the best-fit built-in Shroodler capability for this
specific program, and it's a real testable Role-A-vs-Role-B setup
without needing to build the multi-role extension discussed earlier --
two accounts (admin + created lower-priv user) is exactly what
`authz-diff` already supports.

## Rewards

P1 $4100-4500, P2 $1500-1750, P3 $600-850, P4 $200-250. Avg payout over
the last 3 months: **$1,600**. 202 vulnerabilities rewarded total (heavily
tested program, but still actively paying out).

## Suggested first steps in the new session

1. Confirm the account is actually active (check for a welcome/activation
   email, try logging into app.thousandeyes.com).
2. Log in, look around the dashboard manually first -- get a feel for
   real functionality (tests, alerts, reports, agent management) before
   touching anything. This is worth doing by hand/via browser, not by
   crawling it.
3. Create a second, lower-privileged user within the org (the brief
   explicitly invites this) to set up an `authz-diff` pair.
4. Passively note interesting-looking endpoints/params while browsing
   normally (network tab), rather than running Shroodler's crawler
   against it broadly -- feed anything specific into hand-crafted curl
   requests, mirroring how the PulsePoint and Vienna findings were
   actually found.
5. Remember the required UA string on every request, and the 15-request
   cap if Turbo Intruder is ever genuinely needed for something no other
   tool can test.

## Current testing state (2026-09-08)

Account is live. **Reportable finding drafted, not submitted:**
Regular User can `POST /ajax/sharing/snapshots/{linkId}/update` on
another user's saved event (`*_OWN` not enforced). Republish replaced
the admin public URL (original now 404).

Draft: `reports/thousandeyes/snapshot-own-idor.md`
Notes: `reports/thousandeyes/notes.md`

Finding reconfirmed on a second admin saved event. Bugcrowd draft
is filled (operator submits):
https://bugcrowd.com/engagements/thousandeyes-og/submissions/c5bb212f-245c-45cc-81a1-bd78b1525b7a/edit
Leave the replacement share `cvqkbjqkbdvpvaxhminzuwzadcbgqkgq` until
triage. Connectors still present: `shroodler-probe`, `shroodler-vault`.
