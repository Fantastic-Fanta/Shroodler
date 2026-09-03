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
NPM = "npm_0123456789abcdefghijklmnopqrstuvwxyz"
STRIPE = "sk_test_4eC39HqLyjWDarjtT1zdp7dc"
GOOGLE = "AIzaSyD-app1-fixture-not-real-000000000"
OPENAI = "sk-proj-app1FixtureNotARealOpenAIKey"
SENDGRID = "SG.aaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
HOOK = "https://hooks.slack.com/services/T00000000/B00000000/fixturetokenxx"


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
            NPM,
            STRIPE,
            GOOGLE,
            OPENAI,
            SENDGRID,
            HOOK,
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
    assert "npm-access-token" in found
    assert "stripe-secret-key" in found
    assert "google-api-key" in found
    assert "openai-api-key" in found
    assert "sendgrid-api-key" in found
    assert "slack-webhook" in found

    js = f"const k = '{AWS}';"
    assert "aws-access-key" in _ids(scan_text(js, "http://127.0.0.1/static/app.js"))

    clean = "The quick brown fox jumps over the lazy dog. Hello world."
    assert scan_text(clean, "http://127.0.0.1/about") == []


def test_high_entropy_not_always_secret():
    repeated = "aaaa" * 20
    assert "generic-api-key" not in _ids(scan_text(repeated, "http://127.0.0.1/"))


def test_redaction_never_stores_full_secret():
    findings = scan_text(AWS, "http://127.0.0.1/")
    assert findings
    assert AWS not in (findings[0].evidence or "")
    assert redact(AWS) == findings[0].evidence
