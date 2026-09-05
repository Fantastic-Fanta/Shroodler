package extractors

import "testing"

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

func TestCheckOAuthAuthorizeURLWithState(t *testing.T) {
	findings := CheckOAuthAuthorizeURL("https://idp.example/authorize?response_type=code&client_id=abc&state=xyz123")
	for _, f := range findings {
		if f.ID == "oauth-missing-state" {
			t.Fatal("state is present and non-empty, must not fire oauth-missing-state")
		}
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
