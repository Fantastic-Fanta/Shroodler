package extractors

import (
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

func TestAWSKey(t *testing.T) {
	rules := LoadSecretRules()
	if len(rules) == 0 {
		t.Skip("rules not found from cwd")
	}
	fs := ScanSecrets("AKIAIOSFODNN7EXAMPLE", "http://127.0.0.1/x", rules)
	found := false
	for _, x := range fs {
		if x.ID == "aws-access-key" {
			found = true
		}
	}
	if !found {
		t.Fatal(fs)
	}
}
