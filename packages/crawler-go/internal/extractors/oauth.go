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
	return q.Get("response_type") != "" && q.Get("client_id") != ""
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
	if q.Get("response_type") == "" || q.Get("client_id") == "" {
		return nil
	}
	var findings []models.Finding

	state := q.Get("state")
	if strings.TrimSpace(state) == "" {
		// RFC 7636 defaults code_challenge_method to "plain" when absent,
		// and "plain" sends the verifier itself as the challenge -- it
		// doesn't hide anything in transit/logs the way S256 does, so
		// only an explicit S256 challenge earns the full downgrade;
		// "plain" (or a present-but-unhashed challenge) is real PKCE
		// syntactically but weak enough that this stays at medium rather
		// than being treated as equivalent to a proper S256 challenge.
		codeChallenge := q.Get("code_challenge")
		hasStrongPKCE := codeChallenge != "" && q.Get("code_challenge_method") == "S256"
		severity := "medium"
		description := "OAuth/OIDC authorization request has no state parameter and no S256 " +
			"PKCE challenge, which is what normally protects the redirect callback against " +
			"CSRF (an attacker tricking a victim into completing the attacker's own OAuth flow)"
		if codeChallenge != "" && !hasStrongPKCE {
			description += " (a code_challenge is present but its method isn't S256, which " +
				"doesn't provide the same protection)"
		}
		if hasStrongPKCE {
			// PKCE (code_challenge=S256) binds the authorization code to
			// the client that started the flow and is widely considered
			// adequate CSRF mitigation on its own in modern
			// implementations, so this is downgraded (not dropped --
			// state alongside PKCE is still recommended defense-in-depth
			// per the OAuth Security BCP) rather than treated as the
			// same risk as no CSRF protection at all.
			severity = "low"
			description = "OAuth/OIDC authorization request has no state parameter, though " +
				"code_challenge=S256 (PKCE) is present -- PKCE mitigates most of the CSRF " +
				"risk state normally addresses, but state alongside it is still recommended " +
				"defense-in-depth"
		}
		findings = append(findings, oauthFinding("oauth-missing-state", severity, pageURL, description, pageURL))
	}

	// OIDC's hybrid flow allows a space-separated response_type ("code
	// token", "code id_token token", ...) -- any member being "token"
	// still returns an access token in the redirect fragment, so exact
	// string equality against the whole value would miss every
	// hybrid-flow variant and only catch the pure implicit-flow case.
	responseType := q.Get("response_type")
	for _, part := range strings.Fields(responseType) {
		if part == "token" {
			findings = append(findings, oauthFinding(
				"oauth-implicit-flow",
				"low",
				pageURL,
				"OAuth response_type includes \"token\" (implicit or hybrid flow), which "+
					"returns an access token directly in the redirect URI fragment, exposed to "+
					"browser history/referrer leakage/redirector logs; OAuth 2.1 and current "+
					"best practice deprecate this in favor of the authorization code flow (+ PKCE)",
				responseType,
			))
			break
		}
	}

	return findings
}
