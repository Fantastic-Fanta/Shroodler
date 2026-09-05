package extractors

import (
	"net/url"
	"strings"

	"github.com/shroodler/crawler-go/internal/models"
)

// IsAuthorizationRequest identifies an OAuth 2.0 / OIDC authorization
// request per RFC 6749 s4.1.1: response_type and client_id are the two
// spec-required parameters for exactly this request type, so there is no
// ambiguity in deciding whether a URL is one.
func IsAuthorizationRequest(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	q := u.Query()
	return q.Get("response_type") != "" && q.Has("client_id")
}

func oauthFinding(id, severity, pageURL, description, evidence string) models.Finding {
	return models.Finding{
		ID: id, Severity: severity, Category: "auth", URL: pageURL,
		Description: description, Evidence: &evidence,
	}
}

// CheckOAuthAuthorizeURL is purely passive (inspects the URL's own query
// string, no extra requests) -- the Go port of shroodler's
// extractors/oauth.py, kept in parity rather than excluded from
// run_parity.py's comparison since it's simple enough to implement
// identically in both engines.
func CheckOAuthAuthorizeURL(pageURL string) []models.Finding {
	u, err := url.Parse(pageURL)
	if err != nil {
		return nil
	}
	q := u.Query()
	if q.Get("response_type") == "" || !q.Has("client_id") {
		return nil
	}
	var findings []models.Finding

	state := q.Get("state")
	if strings.TrimSpace(state) == "" {
		findings = append(findings, oauthFinding(
			"oauth-missing-state",
			"medium",
			pageURL,
			"OAuth/OIDC authorization request has no state parameter, which is what "+
				"normally protects the redirect callback against CSRF (an attacker tricking "+
				"a victim into completing the attacker's own OAuth flow)",
			pageURL,
		))
	}

	if q.Get("response_type") == "token" {
		findings = append(findings, oauthFinding(
			"oauth-implicit-flow",
			"low",
			pageURL,
			"OAuth response_type=token (implicit flow) returns the access token "+
				"directly in the redirect URI fragment, exposed to browser history/referrer "+
				"leakage/redirector logs; OAuth 2.1 and current best practice deprecate it in "+
				"favor of the authorization code flow (+ PKCE)",
			"token",
		))
	}

	return findings
}
