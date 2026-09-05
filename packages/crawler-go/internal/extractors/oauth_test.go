package extractors

import (
	"strings"
	"testing"

	"github.com/shroodler/crawler-go/internal/models"
)

func TestIsAuthorizationRequest(t *testing.T) {
	if !IsAuthorizationRequest("https://idp.example/authorize?response_type=code&client_id=abc&state=xyz") {
		t.Fatal("expected response_type+client_id URL to be recognized as an authorization request")
	}
	if IsAuthorizationRequest("https://example.com/?client_id=abc") {
		t.Fatal("missing response_type must not be recognized")
	}
	if IsAuthorizationRequest("https://example.com/?response_type=code") {
		t.Fatal("missing client_id must not be recognized")
	}
}

func TestCheckOAuthAuthorizeURLMissingState(t *testing.T) {
	findings := CheckOAuthAuthorizeURL("https://idp.example/authorize?response_type=code&client_id=abc")
	found := false
	for _, f := range findings {
		if f.ID == "oauth-missing-state" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected oauth-missing-state when state param is absent")
	}
}

func TestCheckOAuthAuthorizeURLMissingStateWithPKCEIsDowngraded(t *testing.T) {
	// code_challenge (PKCE) mitigates most of the CSRF risk state
	// normally addresses -- must not be scored the same as no CSRF
	// protection at all.
	findings := CheckOAuthAuthorizeURL(
		"https://idp.example/authorize?response_type=code&client_id=abc" +
			"&code_challenge=abc123&code_challenge_method=S256",
	)
	var hit *models.Finding
	for i := range findings {
		if findings[i].ID == "oauth-missing-state" {
			hit = &findings[i]
		}
	}
	if hit == nil {
		t.Fatal("expected oauth-missing-state to still fire")
	}
	if hit.Severity != "low" {
		t.Fatalf("expected low severity with PKCE present, got %s", hit.Severity)
	}
	if !strings.Contains(strings.ToLower(hit.Description), "pkce") {
		t.Fatalf("expected description to mention PKCE, got %q", hit.Description)
	}
}

func TestCheckOAuthAuthorizeURLWithState(t *testing.T) {
	findings := CheckOAuthAuthorizeURL("https://idp.example/authorize?response_type=code&client_id=abc&state=xyz123")
	for _, f := range findings {
		if f.ID == "oauth-missing-state" {
			t.Fatal("state is present and non-empty, must not fire oauth-missing-state")
		}
	}
}

func TestCheckOAuthAuthorizeURLRepeatedStateWithBlankFirstValue(t *testing.T) {
	// Regression test for a real Python/Go parity gap caught in review:
	// Go's net/url.Values.Get returns the FIRST value in a repeated
	// param's list ("" here), which Python's parse_qs used to silently
	// drop instead of keeping -- both engines must agree the first
	// occurrence decides, blank or not.
	findings := CheckOAuthAuthorizeURL("https://idp.example/authorize?response_type=code&client_id=abc&state=&state=real")
	found := false
	for _, f := range findings {
		if f.ID == "oauth-missing-state" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected oauth-missing-state when the first state occurrence is blank")
	}
}

func TestCheckOAuthAuthorizeURLEmptyState(t *testing.T) {
	findings := CheckOAuthAuthorizeURL("https://idp.example/authorize?response_type=code&client_id=abc&state=")
	found := false
	for _, f := range findings {
		if f.ID == "oauth-missing-state" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected oauth-missing-state when state param is present but empty")
	}
}

func TestCheckOAuthAuthorizeURLImplicitFlow(t *testing.T) {
	findings := CheckOAuthAuthorizeURL("https://idp.example/authorize?response_type=token&client_id=abc&state=xyz")
	found := false
	for _, f := range findings {
		if f.ID == "oauth-implicit-flow" {
			found = true
			if f.Severity != "low" {
				t.Fatalf("expected low severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatal("expected oauth-implicit-flow for response_type=token")
	}
}

func TestCheckOAuthAuthorizeURLCodeFlowNoImplicitFinding(t *testing.T) {
	findings := CheckOAuthAuthorizeURL("https://idp.example/authorize?response_type=code&client_id=abc&state=xyz")
	for _, f := range findings {
		if f.ID == "oauth-implicit-flow" {
			t.Fatal("response_type=code must not trigger oauth-implicit-flow")
		}
	}
}

func TestCheckOAuthAuthorizeURLNonAuthorizeURLIsIgnored(t *testing.T) {
	findings := CheckOAuthAuthorizeURL("https://example.com/search?q=hello")
	if len(findings) != 0 {
		t.Fatalf("expected no findings for a non-authorization URL, got %v", findings)
	}
}
