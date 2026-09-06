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

func TestCheckOAuthAuthorizeURLMissingStateWithPlainPKCEStaysMedium(t *testing.T) {
	// "plain" sends the verifier itself as the challenge -- it doesn't
	// hide anything the way S256 does, so it must not earn the same
	// downgrade as a real S256 challenge.
	findings := CheckOAuthAuthorizeURL(
		"https://idp.example/authorize?response_type=code&client_id=abc" +
			"&code_challenge=abc123&code_challenge_method=plain",
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
	if hit.Severity != "medium" {
		t.Fatalf("expected medium severity with plain (non-S256) PKCE, got %s", hit.Severity)
	}
}

func TestCheckOAuthAuthorizeURLMissingStateWithCodeChallengeButNoMethodStaysMedium(t *testing.T) {
	// code_challenge_method defaults to "plain" per RFC 7636 when absent.
	findings := CheckOAuthAuthorizeURL(
		"https://idp.example/authorize?response_type=code&client_id=abc&code_challenge=abc123",
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
	if hit.Severity != "medium" {
		t.Fatalf("expected medium severity, got %s", hit.Severity)
	}
}

func TestCheckOAuthAuthorizeURLHybridFlowIsFlaggedAsImplicit(t *testing.T) {
	// OIDC hybrid flow: response_type is space-separated and "token"
	// being one of several values still exposes a token in the fragment.
	findings := CheckOAuthAuthorizeURL(
		"https://idp.example/authorize?response_type=code+token&client_id=abc&state=xyz",
	)
	found := false
	for _, f := range findings {
		if f.ID == "oauth-implicit-flow" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected oauth-implicit-flow for response_type=code token (hybrid)")
	}
}

func TestCheckOAuthAuthorizeURLHybridCodeIDTokenWithoutBareTokenIsNotFlagged(t *testing.T) {
	findings := CheckOAuthAuthorizeURL(
		"https://idp.example/authorize?response_type=code+id_token&client_id=abc&state=xyz",
	)
	for _, f := range findings {
		if f.ID == "oauth-implicit-flow" {
			t.Fatal("response_type=code id_token (no bare token) must not trigger oauth-implicit-flow")
		}
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

func TestMalformedQueryIsNotAssessed(t *testing.T) {
	// Regression test for a real Python/Go parity gap caught in review:
	// url.Query() (via url.ParseQuery) silently drops a pair whose value
	// contains a bare ";" or an invalid %-escape, discarding the parse
	// error -- while Python's parse_qs is lenient and keeps the raw
	// text. That made this engine treat state as *absent* on "state=a;b"
	// (a false oauth-missing-state on a URL that DOES carry a state
	// value). Both engines now refuse to assess a query with either red
	// flag at all -- verified byte-identical against Python over an
	// adversarial corpus during review.
	if IsAuthorizationRequest("https://idp.example/authorize?response_type=code&client_id=abc&state=a;b") {
		t.Fatal("a query containing a bare ';' must not be assessed at all")
	}
	for _, u := range []string{
		"https://idp.example/authorize?response_type=code&client_id=abc&state=a;b",
		"https://idp.example/authorize?response_type=code&client_id=abc&state=%zz",
		"https://idp.example/authorize?response_type=code&client_id=abc&state=%",
	} {
		if got := CheckOAuthAuthorizeURL(u); len(got) != 0 {
			t.Fatalf("expected no findings for malformed query %q, got %v", u, got)
		}
	}
}

func TestJARAndPARRequestsAreNotFlaggedMissingState(t *testing.T) {
	// RFC 9101 (JAR) / RFC 9126 (PAR): response_type+client_id stay in
	// the query for OAuth2 compatibility even when the real parameters
	// (state included) are inside a signed request object or held
	// server-side -- state genuinely can't be assessed passively, and
	// this is a MORE secure deployment shape, not a less secure one.
	for _, u := range []string{
		"https://idp.example/authorize?response_type=code&client_id=abc&request=eyJhbGciOiJSUzI1NiJ9.payload.sig",
		"https://idp.example/authorize?response_type=code&client_id=abc&request_uri=urn:ietf:params:oauth:request_uri:abc",
	} {
		if got := CheckOAuthAuthorizeURL(u); len(got) != 0 {
			t.Fatalf("expected no findings for JAR/PAR request %q, got %v", u, got)
		}
	}
}

func TestWhitespaceOnlyCodeChallengeIsNotTreatedAsPKCE(t *testing.T) {
	findings := CheckOAuthAuthorizeURL(
		"https://idp.example/authorize?response_type=code&client_id=abc" +
			"&state=%20&code_challenge=%20&code_challenge_method=S256",
	)
	var hit *models.Finding
	for i := range findings {
		if findings[i].ID == "oauth-missing-state" {
			hit = &findings[i]
		}
	}
	if hit == nil {
		t.Fatal("expected oauth-missing-state to fire")
	}
	if hit.Severity != "medium" {
		t.Fatalf("expected medium severity for whitespace-only code_challenge, got %s", hit.Severity)
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
			if f.Severity != "medium" {
				t.Fatalf("expected medium severity, got %s", f.Severity)
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
