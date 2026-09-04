package extractors

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func b64(v map[string]any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

func signJWT(header, payload map[string]any, secret string) string {
	h, p := b64(header), b64(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(h + "." + p))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return h + "." + p + "." + sig
}

func TestFindJWTsDedupes(t *testing.T) {
	tok := signJWT(map[string]any{"alg": "HS256"}, map[string]any{"sub": "1"}, "secret")
	text := fmt.Sprintf("Authorization: Bearer %s\nsame again %s", tok, tok)
	found := FindJWTs(text)
	if len(found) != 1 || found[0] != tok {
		t.Fatalf("expected 1 deduped token, got %#v", found)
	}
}

func TestCrackWeakJWTSecretFindsKnownSecret(t *testing.T) {
	tok := signJWT(map[string]any{"alg": "HS256", "typ": "JWT"}, map[string]any{"sub": "1", "exp": 9999999999}, "changeme")
	secret, ok := CrackWeakJWTSecret(tok)
	if !ok || secret != "changeme" {
		t.Fatalf("expected changeme, got %q ok=%v", secret, ok)
	}
}

func TestCrackWeakJWTSecretMissesStrongSecret(t *testing.T) {
	tok := signJWT(map[string]any{"alg": "HS256"}, map[string]any{"sub": "1"}, "a-genuinely-random-64-char-secret-nobody-would-guess-ever-12345")
	if _, ok := CrackWeakJWTSecret(tok); ok {
		t.Fatal("should not crack a strong secret")
	}
}

func TestCrackWeakJWTSecretIgnoresNonHMAC(t *testing.T) {
	tok := signJWT(map[string]any{"alg": "RS256"}, map[string]any{"sub": "1"}, "secret")
	if _, ok := CrackWeakJWTSecret(tok); ok {
		t.Fatal("should not attempt non-HMAC algorithms")
	}
}

func TestAuditJWTFlagsAlgNone(t *testing.T) {
	tok := signJWT(map[string]any{"alg": "none"}, map[string]any{"sub": "1", "exp": 9999999999}, "")
	findings := AuditJWT(tok, "http://127.0.0.1/")
	found := false
	for _, f := range findings {
		if f.ID == "jwt-alg-none" {
			found = true
			if f.Severity != "critical" {
				t.Fatalf("expected critical severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatalf("expected jwt-alg-none, got %#v", findings)
	}
}

func TestAuditJWTFlagsMissingExp(t *testing.T) {
	tok := signJWT(map[string]any{"alg": "HS256"}, map[string]any{"sub": "1"}, "a-genuinely-random-64-char-secret-nobody-would-guess-ever-12345")
	findings := AuditJWT(tok, "http://127.0.0.1/")
	found := false
	for _, f := range findings {
		if f.ID == "jwt-missing-exp" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected jwt-missing-exp, got %#v", findings)
	}
}

func TestAuditJWTFlagsLongExpiry(t *testing.T) {
	farFuture := time.Now().Add(400 * 24 * time.Hour).Unix()
	tok := signJWT(map[string]any{"alg": "HS256"}, map[string]any{"sub": "1", "exp": farFuture}, "a-genuinely-random-64-char-secret-nobody-would-guess-ever-12345")
	findings := AuditJWT(tok, "http://127.0.0.1/")
	found := false
	for _, f := range findings {
		if f.ID == "jwt-long-expiry" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected jwt-long-expiry, got %#v", findings)
	}
}

func TestAuditJWTFlagsWeakSecret(t *testing.T) {
	tok := signJWT(map[string]any{"alg": "HS256"}, map[string]any{"sub": "1", "exp": 9999999999}, "secret")
	findings := AuditJWT(tok, "http://127.0.0.1/")
	found := false
	for _, f := range findings {
		if f.ID == "jwt-weak-secret" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected jwt-weak-secret, got %#v", findings)
	}
}

func TestAuditJWTCleanTokenHasNoFindings(t *testing.T) {
	soon := time.Now().Add(time.Hour).Unix()
	tok := signJWT(map[string]any{"alg": "HS256"}, map[string]any{"sub": "1", "exp": soon}, "a-genuinely-random-64-char-secret-nobody-would-guess-ever-12345")
	findings := AuditJWT(tok, "http://127.0.0.1/")
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %#v", findings)
	}
}

func TestAuditJWTsInTextScansAllTokens(t *testing.T) {
	weak := signJWT(map[string]any{"alg": "HS256"}, map[string]any{"sub": "1", "exp": 9999999999}, "secret")
	text := "<script>const t = '" + weak + "';</script>"
	findings := AuditJWTsInText(text, "http://127.0.0.1/app.js")
	found := false
	for _, f := range findings {
		if f.ID == "jwt-weak-secret" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected jwt-weak-secret, got %#v", findings)
	}
}

func TestAuditJWTMalformedTokenReturnsNil(t *testing.T) {
	if got := AuditJWT("not.a.jwt.at.all", "http://127.0.0.1/"); got != nil {
		t.Fatalf("expected nil, got %#v", got)
	}
	if got := AuditJWT("eyJ.not-base64!!.x", "http://127.0.0.1/"); got != nil {
		t.Fatalf("expected nil, got %#v", got)
	}
}
