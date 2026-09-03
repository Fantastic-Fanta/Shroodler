package extractors

import "testing"

func findingIDs(headers []string, pageURL string) map[string]bool {
	_, findings := ExtractCookies(headers, pageURL)
	out := map[string]bool{}
	for _, f := range findings {
		out[f.ID] = true
	}
	return out
}

func TestCookiePathBroadOnSessionRootPath(t *testing.T) {
	ids := findingIDs([]string{"session_id=abc; Path=/; HttpOnly; SameSite=Lax"}, "http://127.0.0.1/dashboard")
	if !ids["cookie-path-broad"] {
		t.Fatal("expected cookie-path-broad")
	}
	if !ids["insecure-cookie"] {
		t.Fatal("expected insecure-cookie")
	}
}

func TestCookiePathBroadNotOnRestrictedOrNonSession(t *testing.T) {
	restricted := findingIDs([]string{"session_id=abc; Path=/account; HttpOnly; SameSite=Lax"}, "http://127.0.0.1/account")
	if restricted["cookie-path-broad"] {
		t.Fatal("restricted path should not be cookie-path-broad")
	}
	omitted := findingIDs([]string{"session_id=abc; HttpOnly; SameSite=Lax"}, "http://127.0.0.1/dashboard")
	if omitted["cookie-path-broad"] {
		t.Fatal("omitted Path should not be cookie-path-broad")
	}
	prefs := findingIDs([]string{"prefs=1; Path=/; HttpOnly; SameSite=Lax"}, "http://127.0.0.1/dashboard")
	if prefs["cookie-path-broad"] {
		t.Fatal("non-session Path=/ should not be cookie-path-broad")
	}
}

func TestCookieDomainBroadLoopbackAndParent(t *testing.T) {
	loopback := findingIDs([]string{"prefs=1; Path=/; Domain=example.com; HttpOnly; SameSite=Lax"}, "http://127.0.0.1/dashboard")
	if !loopback["cookie-domain-broad"] {
		t.Fatal("example.com on 127.0.0.1 should be cookie-domain-broad")
	}
	parent := findingIDs([]string{"sid=1; Path=/; Domain=example.com; Secure; HttpOnly; SameSite=Lax"}, "https://app.example.com/dash")
	if !parent["cookie-domain-broad"] {
		t.Fatal("parent Domain should be cookie-domain-broad")
	}
}

func TestCookieDomainBroadFalsePositives(t *testing.T) {
	hostOnly := findingIDs([]string{"session_id=abc; Path=/; HttpOnly; SameSite=Lax"}, "http://127.0.0.1/dashboard")
	if hostOnly["cookie-domain-broad"] {
		t.Fatal("host-only cookie should not be cookie-domain-broad")
	}
	exact := findingIDs([]string{"sid=1; Domain=app.example.com; Secure; HttpOnly; SameSite=Lax"}, "https://app.example.com/dash")
	if exact["cookie-domain-broad"] {
		t.Fatal("exact Domain match should not be cookie-domain-broad")
	}
	sibling := findingIDs([]string{"sid=1; Domain=other.com; Secure; HttpOnly; SameSite=Lax"}, "https://app.example.com/dash")
	if sibling["cookie-domain-broad"] {
		t.Fatal("unrelated Domain should not be treated as a parent suffix")
	}
}

func TestCookieMissingHostPrefixHTTPSSession(t *testing.T) {
	ids := findingIDs([]string{"session_id=abc; Path=/; Secure; HttpOnly; SameSite=Strict"}, "https://app.example.com/dash")
	if !ids["cookie-missing-host-prefix"] {
		t.Fatal("expected cookie-missing-host-prefix")
	}
	if ids["cookie-missing-secure-prefix"] {
		t.Fatal("host-prefix candidate should not also flag missing-secure-prefix")
	}
	if !ids["cookie-path-broad"] {
		t.Fatal("expected cookie-path-broad")
	}
}

func TestCookieMissingSecurePrefixWhenHostInapplicable(t *testing.T) {
	withDomain := findingIDs([]string{"session_id=abc; Path=/; Domain=app.example.com; Secure; HttpOnly; SameSite=Lax"}, "https://app.example.com/dash")
	if !withDomain["cookie-missing-secure-prefix"] {
		t.Fatal("expected cookie-missing-secure-prefix with Domain")
	}
	if withDomain["cookie-missing-host-prefix"] {
		t.Fatal("Domain set cannot use __Host-")
	}
	nested := findingIDs([]string{"session_id=abc; Path=/account; Secure; HttpOnly; SameSite=Lax"}, "https://app.example.com/account")
	if !nested["cookie-missing-secure-prefix"] {
		t.Fatal("expected cookie-missing-secure-prefix with nested Path")
	}
	if nested["cookie-missing-host-prefix"] {
		t.Fatal("nested Path cannot use __Host-")
	}
}

func TestCookiePrefixFalsePositives(t *testing.T) {
	alreadyHost := findingIDs([]string{"__Host-session_id=abc; Path=/; Secure; HttpOnly; SameSite=Strict"}, "https://app.example.com/dash")
	if alreadyHost["cookie-missing-host-prefix"] || alreadyHost["cookie-missing-secure-prefix"] {
		t.Fatal("__Host- cookie should not flag missing prefixes")
	}
	alreadySecure := findingIDs([]string{"__Secure-session_id=abc; Path=/account; Secure; HttpOnly; SameSite=Lax"}, "https://app.example.com/account")
	if alreadySecure["cookie-missing-secure-prefix"] {
		t.Fatal("__Secure- cookie should not flag missing-secure-prefix")
	}
	httpLocal := findingIDs([]string{"session_id=abc; Path=/; HttpOnly; SameSite=Lax"}, "http://127.0.0.1/dashboard")
	if httpLocal["cookie-missing-host-prefix"] || httpLocal["cookie-missing-secure-prefix"] {
		t.Fatal("HTTP should not flag cookie prefixes")
	}
	noSecure := findingIDs([]string{"session_id=abc; Path=/; HttpOnly; SameSite=Lax"}, "https://app.example.com/dash")
	if noSecure["cookie-missing-host-prefix"] || noSecure["cookie-missing-secure-prefix"] {
		t.Fatal("missing Secure should not flag cookie prefixes")
	}
	prefs := findingIDs([]string{"prefs=1; Path=/; Secure; HttpOnly; SameSite=Lax"}, "https://app.example.com/dash")
	if prefs["cookie-missing-host-prefix"] || prefs["cookie-missing-secure-prefix"] {
		t.Fatal("non-session cookie should not flag prefixes")
	}
}

func TestCookieSameSiteNoneWithoutSecure(t *testing.T) {
	ids := findingIDs([]string{"open=1; SameSite=None"}, "http://127.0.0.1/")
	if !ids["cookie-samesite-none-without-secure"] {
		t.Fatal("expected cookie-samesite-none-without-secure")
	}
}
