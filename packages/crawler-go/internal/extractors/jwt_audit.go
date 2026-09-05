package extractors

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"hash"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/shroodler/crawler-go/internal/models"
)

var jwtRe = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`)

// weakJWTSecrets is a small, fast common-secret wordlist for HMAC
// weak-secret cracking -- deliberately short so JWT auditing doesn't
// meaningfully slow a crawl down. Kept in sync with
// packages/crawler-py/shroodler/extractors/jwt_audit.py's _WEAK_SECRETS.
var weakJWTSecrets = []string{
	"secret", "password", "123456", "changeme", "changeit", "admin",
	"jwt_secret", "jwtsecret", "your-256-bit-secret", "secretkey",
	"secret_key", "key", "test", "testing", "dev", "development",
	"production", "supersecret", "super-secret", "mysecret", "s3cr3t",
	"qwerty", "letmein", "shroodler", "shhh", "topsecret", "0000", "1234",
	"abc123", "",
}

const longJWTExpiry = 365 * 24 * time.Hour

func b64urlDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// FindJWTs returns every distinct JWT-shaped substring in text, in order
// of first appearance.
func FindJWTs(text string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range jwtRe.FindAllString(text, -1) {
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	return out
}

// CrackWeakJWTSecret tries a small common-secret wordlist against an
// HS256/384/512 JWT's signature. Returns the recovered secret and true if
// found; non-HMAC algorithms and malformed tokens are not attempted.
func CrackWeakJWTSecret(token string) (string, bool) {
	parts := splitJWT(token)
	if parts == nil {
		return "", false
	}
	headerB, err := b64urlDecode(parts[0])
	if err != nil {
		return "", false
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerB, &header); err != nil {
		return "", false
	}
	var newHash func() hash.Hash
	switch header.Alg {
	case "HS256":
		newHash = sha256.New
	case "HS384":
		newHash = sha512.New384
	case "HS512":
		newHash = sha512.New
	default:
		return "", false
	}
	targetSig, err := b64urlDecode(parts[2])
	if err != nil {
		return "", false
	}
	signingInput := []byte(parts[0] + "." + parts[1])
	for _, candidate := range weakJWTSecrets {
		mac := hmac.New(newHash, []byte(candidate))
		mac.Write(signingInput)
		sum := mac.Sum(nil)
		if subtle.ConstantTimeCompare(sum, targetSig) == 1 {
			return candidate, true
		}
	}
	return "", false
}

func splitJWT(token string) []string {
	var parts []string
	start := 0
	for i, c := range token {
		if c == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
		}
	}
	parts = append(parts, token[start:])
	if len(parts) != 3 {
		return nil
	}
	return parts
}

func jwtEvidence(token string) string {
	if len(token) <= 40 {
		return token
	}
	return token[:20] + "..." + token[len(token)-8:]
}

// AuditJWT decodes a single JWT (without verifying it -- there is nothing
// to verify a forged/unsigned token against) and flags alg:none, missing
// or unusually long expiry, and weak HMAC secrets.
func AuditJWT(token, pageURL string) []models.Finding {
	parts := splitJWT(token)
	if parts == nil {
		return nil
	}
	headerB, err := b64urlDecode(parts[0])
	if err != nil {
		return nil
	}
	var header struct {
		Alg string `json:"alg"`
	}
	_ = json.Unmarshal(headerB, &header)

	payloadB, _ := b64urlDecode(parts[1])
	var payload map[string]any
	_ = json.Unmarshal(payloadB, &payload)

	var out []models.Finding
	ev := jwtEvidence(token)

	if strings.ToLower(header.Alg) == "none" {
		desc := "JWT declares \"alg\":\"none\" -- if the server accepts this " +
			"token without verifying a signature, an attacker can forge " +
			"arbitrary claims (full authentication/authorization bypass). " +
			"Try replaying this token with the signature stripped."
		out = append(out, models.Finding{
			ID: "jwt-alg-none", Severity: "critical", Category: "secret",
			URL: pageURL, Description: desc, Evidence: &ev,
		})
	}

	if payload != nil {
		expRaw, hasExp := payload["exp"]
		if !hasExp {
			desc := "JWT has no \"exp\" claim -- the token never expires."
			out = append(out, models.Finding{
				ID: "jwt-missing-exp", Severity: "medium", Category: "secret",
				URL: pageURL, Description: desc, Evidence: &ev,
			})
		} else if expSeconds, ok := asFloat(expRaw); ok {
			exp := time.Unix(int64(expSeconds), 0).UTC()
			if time.Until(exp) > longJWTExpiry {
				desc := "JWT expiry is unusually far in the future (" +
					exp.Format("2006-01-02") +
					"); a leaked long-lived token stays usable for a long time."
				out = append(out, models.Finding{
					ID: "jwt-long-expiry", Severity: "low", Category: "secret",
					URL: pageURL, Description: desc, Evidence: &ev,
				})
			}
		}
	}

	// Deliberately do NOT include the recovered secret itself: this finding
	// (and its evidence) ends up in JSON/HTML/SARIF/JUnit reports that
	// circulate far more widely than the vulnerable app (tickets, CI logs,
	// archived scans) -- printing a live signing secret there would itself
	// be a leak. Re-run CrackWeakJWTSecret manually if you need the value.
	if secret, ok := CrackWeakJWTSecret(token); ok {
		shown := "(empty string)"
		if secret != "" {
			shown = strconv.Itoa(len(secret)) + "-character common secret"
		}
		desc := "JWT signature was reproduced using a " + shown +
			" from a short built-in wordlist -- an attacker can forge arbitrary " +
			"tokens for this application."
		out = append(out, models.Finding{
			ID: "jwt-weak-secret", Severity: "critical", Category: "secret",
			URL: pageURL, Description: desc, Evidence: &ev,
		})
	}

	return out
}

// AuditJWTsInText finds and audits every JWT-shaped token in text.
func AuditJWTsInText(text, pageURL string) []models.Finding {
	var out []models.Finding
	for _, tok := range FindJWTs(text) {
		out = append(out, AuditJWT(tok, pageURL)...)
	}
	return out
}

func asFloat(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case json.Number:
		f, err := t.Float64()
		return f, err == nil
	default:
		return 0, false
	}
}
