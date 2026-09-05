package crawler

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveOneRelativeResolvesAgainstSeedDirectoryNotOrigin(t *testing.T) {
	// A non-rooted relative value must resolve against seed's directory
	// (RFC 3986), not get silently rewritten to an origin-rooted path.
	got := resolveOne("logout", "http://127.0.0.1/account/login")
	want := "http://127.0.0.1/account/logout"
	if got != want {
		t.Fatalf("resolveOne(%q) = %q, want %q", "logout", got, want)
	}
}

func TestResolveOneRootedPathResolvesToOrigin(t *testing.T) {
	got := resolveOne("/logout", "http://127.0.0.1/account/login")
	want := "http://127.0.0.1/logout"
	if got != want {
		t.Fatalf("resolveOne(%q) = %q, want %q", "/logout", got, want)
	}
}

func TestResolveOneAbsoluteURLPassesThrough(t *testing.T) {
	got := resolveOne("https://other.example/logout", "http://127.0.0.1/account/login")
	if got != "https://other.example/logout" {
		t.Fatalf("resolveOne passthrough = %q", got)
	}
}

func TestResolveOneEmptyStaysEmpty(t *testing.T) {
	if got := resolveOne("", "http://127.0.0.1/"); got != "" {
		t.Fatalf("resolveOne(\"\") = %q, want empty", got)
	}
}

func TestLoadLoginRecipeToleratesMalformedOptionalFields(t *testing.T) {
	// A malformed logout_url (wrong JSON type) must degrade to "field
	// absent" -- disabling just the logout-invalidation check -- rather
	// than failing the whole recipe parse and aborting the crawl.
	dir := t.TempDir()
	path := filepath.Join(dir, "recipe.json")
	body := `{"url": "http://127.0.0.1/login", "logout_url": 12345, "protected_url": {"bad": true}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	recipe, err := LoadLoginRecipe(path)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if recipe.LogoutURL != "" || recipe.ProtectedURL != "" {
		t.Fatalf("expected malformed fields to be treated as absent, got %#v", recipe)
	}
}

func TestLoadLoginRecipeAcceptsValidOptionalFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "recipe.json")
	body := `{"url": "http://127.0.0.1/login", "logout_url": "/logout", "protected_url": "/account", "logout_method": "POST"}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	recipe, err := LoadLoginRecipe(path)
	if err != nil {
		t.Fatal(err)
	}
	if recipe.LogoutURL != "/logout" || recipe.ProtectedURL != "/account" || recipe.LogoutMethod != "POST" {
		t.Fatalf("unexpected recipe %#v", recipe)
	}
}
