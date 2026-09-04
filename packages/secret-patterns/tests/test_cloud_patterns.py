from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]

# Documentation-shaped fakes — match the public regex, not live credentials.
GITHUB_PAT = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
GITHUB_FG = (
    "github_pat_11AAAAAAA0FAKESECRET00_"
    "abcdefghijklmnopqrstuvwxyz0123456789FAKESECRETNOTREAL000000"
)
NPM = "npm_0123456789abcdefghijklmnopqrstuvwxyz"
# Composed rather than a single literal so the source never contains a
# string shaped like a real Stripe key (provider-partnered secret scanners
# match on format alone, regardless of how obviously fake the content is).
_FAKE_KEY_BODY = "ShroodlerFakeStripeKey000000"
STRIPE_TEST = f"sk_test_{_FAKE_KEY_BODY}"
STRIPE_LIVE = f"sk_live_{_FAKE_KEY_BODY}"
STRIPE_PK_TEST = "pk_test_51NotASecretPublishableKey000"
STRIPE_PK_LIVE = "pk_live_51NotASecretPublishableKey000"
GOOGLE = "AIzaSyD-app1-fixture-not-real-000000000"
AZURE_KEY = (
    "ShroodlerFakeAzureStorageAccountKey00"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
)
AZURE = f"AccountKey={AZURE_KEY}"
AZURE_SHARED = f"SharedAccessKey={AZURE_KEY}"


def _rules_by_id() -> dict[str, dict]:
    out: dict[str, dict] = {}
    for path in sorted((ROOT / "rules").glob("*.yaml")):
        for rule in yaml.safe_load(path.read_text(encoding="utf-8")):
            out[rule["id"]] = rule
    return out


def _compiled() -> dict[str, re.Pattern[str]]:
    compiled: dict[str, re.Pattern[str]] = {}
    for rid, rule in _rules_by_id().items():
        pattern = rule["pattern"]
        if pattern == "__ENTROPY__":
            continue
        compiled[rid] = re.compile(pattern)
    return compiled


def test_cloud_patterns_match_and_non_match():
    rx = _compiled()

    assert rx["github-pat"].search(GITHUB_PAT)
    assert not rx["github-pat"].search("ghp_short")
    assert not rx["github-pat"].search("gho_0123456789abcdefghijklmnopqrstuvwxyz")

    assert rx["github-fine-grained-pat"].search(GITHUB_FG)
    assert not rx["github-fine-grained-pat"].search("github_pat_tooshort")
    assert not rx["github-fine-grained-pat"].search(GITHUB_PAT)

    assert rx["npm-access-token"].search(NPM)
    assert not rx["npm-access-token"].search("npm_short")

    assert rx["stripe-secret-key-test"].search(STRIPE_TEST)
    assert not rx["stripe-secret-key-test"].search(STRIPE_LIVE)
    assert rx["stripe-secret-key-live"].search(STRIPE_LIVE)
    assert not rx["stripe-secret-key-live"].search(STRIPE_TEST)
    assert not rx["stripe-secret-key-test"].search(STRIPE_PK_TEST)
    assert not rx["stripe-secret-key-live"].search(STRIPE_PK_LIVE)
    assert not rx["stripe-secret-key-test"].search("sk_test_short")

    assert rx["google-api-key"].search(GOOGLE)
    assert not rx["google-api-key"].search("AIzaSHORT")
    assert not rx["google-api-key"].search("AIza" + "a" * 34)

    assert len(AZURE_KEY) == 88
    assert rx["azure-storage-account-key"].search(AZURE)
    assert rx["azure-storage-account-key"].search(AZURE_SHARED)
    assert rx["azure-storage-account-key"].search(f'AccountKey="{AZURE_KEY}"')
    assert not rx["azure-storage-account-key"].search(AZURE_KEY)
    assert not rx["azure-storage-account-key"].search("AccountKey=tooshort")
    assert not rx["azure-storage-account-key"].search("AccountName=shroodlerfake")


def test_patterns_compile_and_do_not_crash_on_junk():
    rx = _compiled()
    junk = [
        "",
        "hello world",
        "\x00\x01\xff",
        "A" * 200,
        "pk_test_" + "x" * 40,
        "AccountKey=" + "A" * 40,
        "github_pat_",
        "sk_live_",
    ]
    for pattern in rx.values():
        for text in junk:
            pattern.search(text)


def test_version_changelog_mentions_cloud_pack():
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "## 0.2.0" in changelog
    assert "github_pat_" in changelog
    assert "sk_live_" in changelog
