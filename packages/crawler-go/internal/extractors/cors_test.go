package extractors

import "testing"

func TestCORSFindingsEachID(t *testing.T) {
	wild := CORSFindings(map[string]string{
		"Access-Control-Allow-Origin":      "*",
		"Access-Control-Allow-Credentials": "true",
	}, "http://127.0.0.1/api/x")
	if len(wild) != 1 || wild[0].ID != "cors-wildcard-credentials" || wild[0].Category != "header" || wild[0].Severity != "high" {
		t.Fatalf("wildcard-credentials %#v", wild)
	}

	any := CORSFindings(map[string]string{
		"Access-Control-Allow-Origin": "*",
	}, "http://127.0.0.1/api/x")
	if len(any) != 1 || any[0].ID != "cors-allow-any" || any[0].Severity != "info" {
		t.Fatalf("allow-any %#v", any)
	}

	reflect := CORSFindings(map[string]string{
		"Access-Control-Allow-Origin": AttackerOrigin,
	}, "http://127.0.0.1/api/x")
	if len(reflect) != 1 || reflect[0].ID != "cors-reflect-origin" || reflect[0].Severity != "medium" {
		t.Fatalf("reflect %#v", reflect)
	}

	reflectCreds := CORSFindings(map[string]string{
		"Access-Control-Allow-Origin":      AttackerOrigin,
		"Access-Control-Allow-Credentials": "true",
	}, "http://127.0.0.1/api/x")
	if len(reflectCreds) != 1 || reflectCreds[0].ID != "cors-reflect-origin" || reflectCreds[0].Severity != "high" {
		t.Fatalf("reflect creds %#v", reflectCreds)
	}
}

func TestCORSFindingsNegative(t *testing.T) {
	if got := CORSFindings(map[string]string{
		"Access-Control-Allow-Origin": "https://app.example",
	}, "http://127.0.0.1/api/x"); len(got) != 0 {
		t.Fatalf("allowlist %#v", got)
	}
	if got := CORSFindings(map[string]string{}, "http://127.0.0.1/api/x"); len(got) != 0 {
		t.Fatalf("absent %#v", got)
	}
}

func TestIsAPIIshSkipsStatic(t *testing.T) {
	if !IsStaticAsset("http://127.0.0.1/static/app.js") {
		t.Fatal("js should be static")
	}
	if IsAPIIsh("http://127.0.0.1/static/app.js", "application/javascript") {
		t.Fatal("js should not be api-ish")
	}
	if !IsAPIIsh("http://127.0.0.1/api/users", "text/plain") {
		t.Fatal("/api/ should be api-ish")
	}
	if !IsAPIIsh("http://127.0.0.1/users", "application/json") {
		t.Fatal("json should be api-ish")
	}
	if IsAPIIsh("http://127.0.0.1/login", "text/html") {
		t.Fatal("html login should not be api-ish")
	}
}
