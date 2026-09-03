package extractors

import (
	"strings"
	"testing"
)

func FuzzScanSecrets(f *testing.F) {
	f.Add([]byte("hello"))
	f.Add([]byte("AKIAIOSFODNN7EXAMPLE"))
	rules := LoadSecretRules()
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = ScanSecrets(string(data), "http://127.0.0.1/", rules)
	})
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
