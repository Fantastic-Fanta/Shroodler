# Webhook URL Field Accepts Internal/Cloud-Metadata Addresses (SSRF)

**Target:** `app.launchdarkly.com` — Webhooks integration
**Class:** SSRF (CWE-918)
**Severity:** Low–Medium — see Impact note

## Summary

The Webhooks integration (Org Settings → Integrations → Webhooks) accepts any URL,
including internal/cloud-metadata addresses, with no validation. I set a webhook's
`url` to `http://169.254.169.254/latest/meta-data/iam/security-credentials/` (the AWS
metadata SSRF target) via `/api/v2/webhooks` and it was accepted with `200 OK` — no
rejection, on create or update.

## Steps to Reproduce

1. Org Settings → Integrations → Webhooks → Add new.
2. Set URL to `http://169.254.169.254/latest/meta-data/iam/security-credentials/`.
   (API: `PATCH /api/v2/webhooks/{id}`, body
   `[{"op":"replace","path":"/url","value":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}]`,
   `Content-Type: application/json; domain-model=launchdarkly.semanticpatch`.)
3. Save — accepted with no validation error.
4. Trigger a flag change to make the backend attempt delivery.

## Proof the webhook mechanism is real

Before testing the metadata URL, I pointed a webhook at a `webhook.site` URL I control.
LaunchDarkly's server hit it immediately on webhook creation — real POST from
`54.221.221.197` (AWS us-east-1), `User-Agent: LD-Integrations/1.0`. Confirms delivery
is a live, server-initiated request, not just stored config.

## Impact — confirmed vs. not

**Confirmed:** the URL field has no validation against internal/link-local/metadata
ranges; the delivery mechanism genuinely fires outbound requests.

**Not confirmed:** whether a request to `169.254.169.254` actually reaches the
metadata service from your infrastructure, or is blocked by network-level egress
controls first. There's no delivery log, delivery history, or status field anywhere
I could find (`GET /api/v2/webhooks/{id}` has no status field; guessed delivery-log
endpoints all 404'd) — so there's no way for an external tester to see the outcome.
I'm not claiming credential theft, only that the input isn't validated.

## Suggested Fix

Reject webhook URLs resolving to RFC 1918, loopback, or link-local (169.254.0.0/16)
ranges — ideally checked at dispatch time too, not just on save, to prevent
DNS-rebinding bypass.
