package extractors

import (
	"strings"
	"testing"
)

const (
	githubPAT = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
	githubFG  = "github_pat_11AAAAAAA0FAKESECRET00_abcdefghijklmnopqrstuvwxyz0123456789FAKESECRETNOTREAL000000"
	npmTok    = "npm_0123456789abcdefghijklmnopqrstuvwxyz"
	stripeSec = "sk_test_4eC39HqLyjWDarjtT1zdp7dc"
	stripePK  = "pk_test_51NotASecretPublishableKey000"
	googleKey = "AIzaSyD-app1-fixture-not-real-000000000"
	azureKey  = "ShroodlerFakeAzureStorageAccountKey00AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
)

func FuzzScanSecrets(f *testing.F) {
	f.Add([]byte("hello"))
	f.Add([]byte("AKIAIOSFODNN7EXAMPLE"))
	f.Add([]byte(githubPAT))
	f.Add([]byte(stripePK))
	f.Add([]byte("AccountKey=tooshort"))
	rules := LoadSecretRules()
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = ScanSecrets(string(data), "http://127.0.0.1/", rules)
	})
}

func scanIDs(t *testing.T, body string) map[string]bool {
	t.Helper()
	rules := LoadSecretRules()
	if len(rules) == 0 {
		t.Skip("rules not found from cwd")
	}
	found := map[string]bool{}
	for _, x := range ScanSecrets(body, "http://127.0.0.1/x", rules) {
		found[x.ID] = true
	}
	return found
}

func TestAWSKey(t *testing.T) {
	found := scanIDs(t, "AKIAIOSFODNN7EXAMPLE")
	if !found["aws-access-key"] {
		t.Fatal(found)
	}
}

func TestYAMLRulesCoverCloudAndCore(t *testing.T) {
	rules := LoadSecretRules()
	if len(rules) == 0 {
		t.Skip("rules not found from cwd")
	}
	ids := map[string]bool{}
	for _, r := range rules {
		ids[r.ID] = true
	}
	for _, id := range []string{
		"aws-access-key", "github-pat", "stripe-secret-key", "google-api-key",
		"npm-access-token", "sendgrid-api-key", "openai-api-key", "slack-webhook",
	} {
		if !ids[id] {
			t.Fatalf("missing rule %s", id)
		}
	}
	body := strings.Join([]string{
		"AKIAIOSFODNN7EXAMPLE",
		"ghp_0123456789abcdefghijklmnopqrstuvwxyz",
		"sk_test_4eC39HqLyjWDarjtT1zdp7dc",
		"AIzaSyD-app1-fixture-not-real-000000000",
	}, "\n")
	fs := ScanSecrets(body, "http://127.0.0.1/x", rules)
	found := map[string]bool{}
	for _, x := range fs {
		found[x.ID] = true
	}
	if !found["aws-access-key"] || !found["github-pat"] || !found["stripe-secret-key"] {
		t.Fatal(fs)
	}
}

func TestWordlistsAreDataFiles(t *testing.T) {
	paths := LoadCommonPaths()
	if len(paths) == 0 {
		t.Skip("wordlists not found from cwd")
	}
	want := []string{"/.git/config", "/.git/HEAD", "/.well-known/security.txt", "/.env"}
	have := map[string]bool{}
	for _, p := range paths {
		have[p] = true
	}
	for _, w := range want {
		if !have[w] {
			t.Fatalf("missing wordlist path %s in %v", w, paths)
		}
	}
}

func TestCloudYAMLRulesMatchAndNonMatch(t *testing.T) {
	rules := LoadSecretRules()
	if len(rules) == 0 {
		t.Skip("rules not found from cwd")
	}
	ids := map[string]bool{}
	for _, r := range rules {
		ids[r.ID] = true
	}
	for _, id := range []string{
		"github-pat", "github-fine-grained-pat", "npm-access-token",
		"stripe-secret-key", "google-api-key", "azure-storage-account-key",
	} {
		if !ids[id] {
			t.Fatalf("missing rule %s", id)
		}
	}

	azure := "AccountKey=" + azureKey
	body := strings.Join([]string{
		"AKIAIOSFODNN7EXAMPLE",
		githubPAT,
		githubFG,
		npmTok,
		stripeSec,
		"sk_live_ShroodlerFakeStripeKey000000",
		googleKey,
		azure,
	}, "\n")
	found := scanIDs(t, body)
	for _, id := range []string{
		"aws-access-key", "github-pat", "github-fine-grained-pat",
		"npm-access-token", "stripe-secret-key", "google-api-key",
		"azure-storage-account-key",
	} {
		if !found[id] {
			t.Fatalf("missing hit %s in %v", id, found)
		}
	}

	if scanIDs(t, stripePK)["stripe-secret-key"] {
		t.Fatal("publishable pk_ must not match stripe-secret-key")
	}
	if scanIDs(t, "pk_live_51NotASecretPublishableKey000")["stripe-secret-key"] {
		t.Fatal("pk_live_ must not match stripe-secret-key")
	}
	if scanIDs(t, "ghp_short")["github-pat"] {
		t.Fatal("truncated ghp_")
	}
	if scanIDs(t, azureKey)["azure-storage-account-key"] {
		t.Fatal("unprefixed 88-char blob must not match")
	}
	if scanIDs(t, "The quick brown fox jumps over the lazy dog.")["github-pat"] {
		t.Fatal("clean prose")
	}
}

func TestCloudSecretRedactionTruncates(t *testing.T) {
	rules := LoadSecretRules()
	if len(rules) == 0 {
		t.Skip("rules not found from cwd")
	}
	raw := githubPAT
	fs := ScanSecrets(raw, "http://127.0.0.1/", rules)
	if len(fs) == 0 {
		t.Fatal("no findings")
	}
	for _, f := range fs {
		if f.ID != "github-pat" {
			continue
		}
		if f.Evidence == nil {
			t.Fatal("evidence")
		}
		if strings.Contains(*f.Evidence, raw) {
			t.Fatalf("full secret stored: %s", *f.Evidence)
		}
		if !strings.Contains(*f.Evidence, "************") {
			t.Fatalf("not truncated: %s", *f.Evidence)
		}
		if len(*f.Evidence) >= len(raw) {
			t.Fatalf("evidence not shorter than secret: %s", *f.Evidence)
		}
		return
	}
	t.Fatal(fs)
}
