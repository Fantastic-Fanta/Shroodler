package autoresponder

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadBodyFileAndBadPattern(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "body.txt"), []byte("fromfile"), 0o644)
	p := filepath.Join(dir, "r.yaml")
	os.WriteFile(p, []byte("- match:\n    method: GET\n    url_pattern: .\n  respond:\n    status: 201\n    body_file: body.txt\n"), 0o644)
	rules, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(rules[0].Respond.BodyBytes) != "fromfile" {
		t.Fatalf("%s", rules[0].Respond.BodyBytes)
	}
	bad := filepath.Join(dir, "bad.yaml")
	os.WriteFile(bad, []byte("- match:\n    url_pattern: '('\n  respond:\n    status: 200\n"), 0o644)
	if _, err := Load(bad); err == nil {
		t.Fatal("expected pattern error")
	}
	missing := filepath.Join(dir, "miss.yaml")
	os.WriteFile(missing, []byte("- match:\n    url_pattern: .\n  respond:\n    body_file: nope.txt\n"), 0o644)
	if _, err := Load(missing); err == nil {
		t.Fatal("expected body_file error")
	}
}
