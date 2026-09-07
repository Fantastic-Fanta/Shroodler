from __future__ import annotations

from shroodler.extractors.secrets import redact, scan_text

AWS = "AKIAIOSFODNN7EXAMPLE"
SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.abc"
KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----"
SLACK = "xoxb-1234567890-abcdefABCDE"
BASIC = "https://user:pass@127.0.0.1:8081/db"
DB = "postgres://app:secret@127.0.0.1:5432/app1"
ENTROPY = "N9fQ2vL8xR4mK7pW3sT6yH1cB5dG0jA8"
GITHUB = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
GITHUB_FG = (
    "github_pat_11AAAAAAA0FAKESECRET00_"
    "abcdefghijklmnopqrstuvwxyz0123456789FAKESECRETNOTREAL000000"
)
NPM = "npm_0123456789abcdefghijklmnopqrstuvwxyz"
# Composed rather than a single literal so the source never contains a
# string shaped like a real Stripe key (which trips provider-partnered
# secret scanners on format alone, regardless of how obviously fake the
# content is) -- the fixture still exercises the real detection regex.
_FAKE_KEY_BODY = "ShroodlerFixtureNotARealKey0000"
STRIPE = f"sk_test_{_FAKE_KEY_BODY}"
STRIPE_PK = "pk_test_51NotASecretPublishableKey000"
GOOGLE = "AIzaSyD-app1-fixture-not-real-000000000"
OPENAI = "sk-proj-app1FixtureNotARealOpenAIKey"
SENDGRID = "SG.aaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
HOOK = "https://hooks.slack.com/services/T00000000/B00000000/fixturetokenxx"
AZURE_KEY = (
    "ShroodlerFakeAzureStorageAccountKey00"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
)
AZURE = f"AccountKey={AZURE_KEY}"


def _ids(findings) -> set[str]:
    return {f.id for f in findings}


def test_patterns_in_body_and_absent():
    body = "\n".join(
        [
            AWS,
            f'aws_secret_access_key="{SECRET}"',
            JWT,
            KEY,
            SLACK,
            BASIC,
            DB,
            ENTROPY,
            GITHUB,
            GITHUB_FG,
            NPM,
            STRIPE,
            GOOGLE,
            OPENAI,
            SENDGRID,
            HOOK,
            AZURE,
        ]
    )
    found = _ids(scan_text(body, "http://127.0.0.1/page"))
    assert "aws-access-key" in found
    assert "aws-secret-key" in found
    assert "generic-jwt" in found
    assert "private-key-block" in found
    assert "slack-token" in found
    assert "basic-auth-url" in found
    assert "database-connection-string" in found
    assert "github-pat" in found
    assert "github-fine-grained-pat" in found
    assert "npm-access-token" in found
    assert "stripe-secret-key-test" in found
    assert "google-api-key" in found
    assert "openai-api-key" in found
    assert "sendgrid-api-key" in found
    assert "slack-webhook" in found
    assert "azure-storage-account-key" in found

    js = f"const k = '{AWS}'; const g = '{GITHUB}';"
    js_ids = _ids(scan_text(js, "http://127.0.0.1/static/app.js"))
    assert "aws-access-key" in js_ids
    assert "github-pat" in js_ids

    clean = "The quick brown fox jumps over the lazy dog. Hello world."
    assert scan_text(clean, "http://127.0.0.1/about") == []


def test_stripe_publishable_key_is_not_a_secret_hit():
    found = _ids(scan_text(STRIPE_PK, "http://127.0.0.1/js"))
    assert "stripe-secret-key-test" not in found
    assert "stripe-secret-key-live" not in found
    live_pk = scan_text("pk_live_51NotASecretPublishableKey000", "http://127.0.0.1/js")
    live_ids = _ids(live_pk)
    assert "stripe-secret-key-test" not in live_ids
    assert "stripe-secret-key-live" not in live_ids


def test_stripe_live_vs_test_key_severity_differs():
    live = scan_text(f"sk_live_{_FAKE_KEY_BODY}", "http://127.0.0.1/")
    test = scan_text(f"sk_test_{_FAKE_KEY_BODY}", "http://127.0.0.1/")
    live_hit = next(f for f in live if f.id == "stripe-secret-key-live")
    test_hit = next(f for f in test if f.id == "stripe-secret-key-test")
    assert live_hit.severity == "critical"
    assert test_hit.severity != "critical"


def test_cloud_prefixes_do_not_match_truncated_or_unprefixed():
    assert "github-pat" not in _ids(scan_text("ghp_short", "http://127.0.0.1/"))
    assert "npm-access-token" not in _ids(scan_text("npm_short", "http://127.0.0.1/"))
    assert "google-api-key" not in _ids(scan_text("AIzaSHORT", "http://127.0.0.1/"))
    assert "azure-storage-account-key" not in _ids(scan_text(AZURE_KEY, "http://127.0.0.1/"))


def test_high_entropy_not_always_secret():
    repeated = "aaaa" * 20
    assert "generic-api-key" not in _ids(scan_text(repeated, "http://127.0.0.1/"))


def test_aspnet_viewstate_is_not_a_secret_hit():
    # __VIEWSTATE/__EVENTVALIDATION are ASP.NET WebForms' own base64
    # postback state, naturally high-entropy but round-tripped to the
    # same client -- not a secret. Every classic ASP.NET site would
    # otherwise spam a false "possible API key" finding.
    html = (
        '<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" '
        'value="/wEPDwULLTEzNjE4NjMyODFkZNppL3g3vRvyvtsdFh7YkbNIpPK9c8XyzAbQwErTyU">'
        '<input type="hidden" name="__EVENTVALIDATION" id="__EVENTVALIDATION" '
        'value="/wEdAAKp7hN3mQxLzVtRfWbGcJdKsHnYaEoIuPlXoCrTsUvWyBnDqFhZjKmNpQrStUv">'
    )
    assert "generic-api-key" not in _ids(scan_text(html, "http://127.0.0.1/default.aspx"))
    # A real high-entropy token elsewhere on the same page must still fire.
    assert "generic-api-key" in _ids(
        scan_text(html + ENTROPY, "http://127.0.0.1/default.aspx")
    )


def test_url_embedded_benign_params_are_not_generic_api_keys():
    # Map-bookmark / pagination-cursor / tracking IDs trip the same entropy
    # heuristic as a leaked key, with no field name as reliable as ViewState.
    bookmark = f'<a href="/map.aspx?x=1&bookmark={ENTROPY}">map</a>'
    assert "generic-api-key" not in _ids(scan_text(bookmark, "http://127.0.0.1/map"))
    cursor = f'fetch("/items?cursor={ENTROPY}")'
    assert "generic-api-key" not in _ids(scan_text(cursor, "http://127.0.0.1/"))
    # A high-signal param name in a URL is still a finding -- a leaked key
    # that happens to live in a query string must not be silenced.
    leaked = f'<a href="/hook?api_key={ENTROPY}">k</a>'
    assert "generic-api-key" in _ids(scan_text(leaked, "http://127.0.0.1/"))
    # Same token also sitting outside the query string still fires.
    both = f'<a href="/map?bookmark={ENTROPY}"></a><script>const k="{ENTROPY}"</script>'
    assert "generic-api-key" in _ids(scan_text(both, "http://127.0.0.1/"))


def test_false_positive_patterns_not_reported():
    """Tokens that look high-entropy but are known public/structured identifiers."""
    # Google OAuth Client ID — public, always suffixed with .apps.googleusercontent.com
    google_oauth = (
        '"GOOGLE_ONETAP_CLIENT_ID":"1070319902608-plmm2pme29to6s18v4emc53r0h5aknkc'
        '.apps.googleusercontent.com"'
    )
    assert "generic-api-key" not in _ids(scan_text(google_oauth, "http://127.0.0.1/"))

    # Salesforce LiveAgent DevName — structured component identifier, not a secret
    salesforce = 'devName: "EmbeddedServiceLiveAgent_Parent04I080000008P5rEAE_17efd1661c0"'
    assert "generic-api-key" not in _ids(scan_text(salesforce, "http://127.0.0.1/"))

    # Webpack CSS module class names — auto-generated, use __ separator
    css_module = 'class="index-module-scss-module__KdAblW__root"'
    assert "generic-api-key" not in _ids(scan_text(css_module, "http://127.0.0.1/"))

    # Feature flag / config key names (LaunchDarkly-style camelCase identifiers)
    # have 4+ CamelCase word segments and are not secrets
    feature_flag = "compliance.CopyRestrictionCheckAsFirstPriorityEnabled"
    assert "generic-api-key" not in _ids(scan_text(feature_flag, "http://127.0.0.1/"))
    feature_flag2 = '"disableReviewProfileButtonOnBlockedPopupForRegulations":"[1,10]"'
    assert "generic-api-key" not in _ids(scan_text(feature_flag2, "http://127.0.0.1/"))

    # param=UUID should not fire (UUID is a structured identifier, not a secret)
    param_uuid = "affiliatePartnerId=84714d4e-4ee9-44cf-a90c-7a7095995d36"
    assert "generic-api-key" not in _ids(scan_text(param_uuid, "http://127.0.0.1/"))

    # URL-encoded path fragments (token preceded by %) are not secrets
    encoded_path = "https://example.com%2Fsome-long-path-slug-goes-here-with-content"
    assert "generic-api-key" not in _ids(scan_text(encoded_path, "http://127.0.0.1/"))

    # A real random key in the same page must still fire
    real_key = "xK9mP2qR7vL4nB8cJ5tH3wY6uA1dF0eG"
    combined = google_oauth + "\n" + salesforce + "\n" + css_module + "\n" + real_key
    assert "generic-api-key" in _ids(scan_text(combined, "http://127.0.0.1/"))


def test_redaction_never_stores_full_secret():
    findings = scan_text(AWS, "http://127.0.0.1/")
    assert findings
    assert AWS not in (findings[0].evidence or "")
    assert redact(AWS) == findings[0].evidence

    for token, rid in (
        (GITHUB, "github-pat"),
        (STRIPE, "stripe-secret-key-test"),
        (GOOGLE, "google-api-key"),
        (AZURE, "azure-storage-account-key"),
    ):
        hits = [f for f in scan_text(token, "http://127.0.0.1/") if f.id == rid]
        assert hits, rid
        evidence = hits[0].evidence or ""
        assert token not in evidence
        assert "************" in evidence
        assert len(evidence) < len(token)
