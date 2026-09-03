package extractors

import (
	"strings"
	"testing"

	"github.com/shroodler/crawler-go/internal/models"
)

func TestExtractLinksAndForms(t *testing.T) {
	html := `<html><head>
<link rel="stylesheet" href="/s.css">
<meta http-equiv="refresh" content="0;url=/next">
<style>div{background:url(/bg.png)}</style>
</head><body>
<a href="/a">a</a>
<a href="/hp" hidden>h</a>
<form action="/login" method="post" enctype="multipart/form-data">
<input type="password" name="pw" autocomplete="on">
<input name="x" disabled readonly>
<select name="s"></select>
<textarea name="t"></textarea>
</form>
<script src="/app.js"></script>
<div style="background:url(/i.gif)"></div>
</body></html>`
	links := ExtractLinks("http://127.0.0.1/", html)
	joined := strings.Join(links, " ")
	if !strings.Contains(joined, "/a") || strings.Contains(joined, "/hp") {
		t.Fatalf("%v", links)
	}
	forms, findings := ExtractForms(html, "http://127.0.0.1/login")
	if len(forms) != 1 || forms[0].Method != "POST" {
		t.Fatalf("%v", forms)
	}
	if forms[0].Enctype == nil {
		t.Fatal("enctype")
	}
	foundAuto := false
	for _, f := range findings {
		if f.ID == "autocomplete" {
			foundAuto = true
		}
	}
	if !foundAuto {
		t.Fatal(findings)
	}
}

func TestHeadersCookiesSecretsJS(t *testing.T) {
	h, hf := ExtractHeaders(map[string]string{
		"Content-Security-Policy": "default-src 'unsafe-inline'",
		"Server":                  "x/1",
	}, "https://127.0.0.1/")
	if len(hf) == 0 {
		t.Fatalf("headers %#v %#v", h, hf)
	}
	cks, cf := ExtractCookies([]string{"sid=1; Secure; HttpOnly; SameSite=Strict", "open=1"}, "http://127.0.0.1/")
	if len(cks) < 2 || len(cf) == 0 {
		t.Fatalf("%v %v", cks, cf)
	}
	rules := []Rule{
		{ID: "aws-access-key", Pattern: `AKIA[0-9A-Z]{16}`, Severity: "high", Description: "aws"},
		{ID: "generic-api-key", Pattern: "__ENTROPY__", Severity: "medium", Description: "ent"},
		{ID: "generic-jwt", Pattern: `eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`, Severity: "medium", Description: "jwt"},
	}
	body := "AKIAIOSFODNN7EXAMPLE " + strings.Repeat("Ab1/", 12) + " eyJhbGciOiJIUzI1NiJ9.eyJzdWI.sig"
	ss := ScanSecrets(body, "http://127.0.0.1/x", rules)
	if len(ss) == 0 {
		t.Fatal("secrets")
	}
	eps := ExtractJSEndpoints("/app.js", `fetch("/api/v1"); fetch(`+"`/t/${id}`"+`);`)
	if len(eps) == 0 {
		t.Fatal(eps)
	}
	js := "function n(){}\n//# sourceMappingURL=app.min.js.map\n"
	if SourceMappingURL(js) != "app.min.js.map" {
		t.Fatal(SourceMappingURL(js))
	}
	raw := []byte(`{"version":3,"sources":["src/internal.ts"],"sourcesContent":["fetch(\"/api/sourcemap-only\");\n"]}`)
	meps, mf := ParseSourceMap("/static/app.min.js", raw, nil)
	if len(meps) == 0 || meps[0].Endpoint != "/api/sourcemap-only" {
		t.Fatalf("%v", meps)
	}
	if len(mf) == 0 || mf[0].Evidence == nil || !strings.Contains(*mf[0].Evidence, "src/internal.ts") {
		t.Fatalf("%v", mf)
	}
	if DecodeDataURL("data:text/plain,hello") == nil {
		t.Fatal("data url")
	}
	ghosts := GhostRouteFindings("http://127.0.0.1:8081/", []models.Page{{URL: "http://127.0.0.1:8081/static/app.js"}}, []models.JSEndpoint{{Source: "http://127.0.0.1:8081/static/app.js", Endpoint: "/api/never-crawled-ghost"}})
	if len(ghosts) != 1 || ghosts[0].ID != "ghost-route" || ghosts[0].Category != "js-endpoint" {
		t.Fatalf("ghost %+v", ghosts)
	}
	if ghosts[0].URL != "http://127.0.0.1:8081/api/never-crawled-ghost" {
		t.Fatalf("ghost url %s", ghosts[0].URL)
	}
	if ghosts[0].Evidence == nil || !strings.Contains(*ghosts[0].Evidence, "app.js") {
		t.Fatalf("ghost evidence %v", ghosts[0].Evidence)
	}
	visited := GhostRouteFindings("http://127.0.0.1:8081/", []models.Page{{URL: "http://127.0.0.1:8081/api/never-crawled-ghost"}}, []models.JSEndpoint{{Source: "http://127.0.0.1:8081/static/app.js", Endpoint: "/api/never-crawled-ghost"}})
	if len(visited) != 0 {
		t.Fatalf("visited should not be ghost: %+v", visited)
	}
	off := GhostRouteFindings("http://127.0.0.1:8081/", nil, []models.JSEndpoint{{Source: "http://127.0.0.1:8081/static/app.js", Endpoint: "https://evil.example/api/x"}})
	if len(off) != 0 {
		t.Fatalf("cross-origin ghost: %+v", off)
	}
	if len(ScriptSrcs(`<script src="/a.js"></script>`)) == 0 {
		t.Fatal("script")
	}
	rb := ParseRobots("User-agent: *\nDisallow: /secret\n")
	if RobotsAllowed(rb, "/secret") {
		t.Fatal("robots")
	}
	if !RobotsAllowed(rb, "/ok") {
		t.Fatal("allow")
	}
	if PaginationFamily("http://127.0.0.1/page/3") == "" {
		t.Fatal("page fam")
	}
	if PaginationFamily("http://127.0.0.1/x?page=2") == "" {
		t.Fatal("query fam")
	}
	if Hash(strings.NewReader("a")) == Hash(strings.NewReader("b")) {
		t.Fatal("hash")
	}
	_ = Redact("supersecretvalue")
}

func findingHas(fs []models.Finding, id string) bool {
	for _, f := range fs {
		if f.ID == id {
			return true
		}
	}
	return false
}

func TestCSPHeaderFindings(t *testing.T) {
	_, wild := ExtractHeaders(map[string]string{
		"Content-Security-Policy": "script-src *",
		"X-Frame-Options":         "DENY",
	}, "https://127.0.0.1/")
	if !findingHas(wild, "csp-wildcard-script") {
		t.Fatalf("wildcard script-src: %v", wild)
	}
	_, viaDefault := ExtractHeaders(map[string]string{
		"Content-Security-Policy": "default-src *",
		"X-Frame-Options":         "DENY",
	}, "https://127.0.0.1/")
	if !findingHas(viaDefault, "csp-wildcard-script") {
		t.Fatalf("wildcard default-src: %v", viaDefault)
	}
	_, httpsScheme := ExtractHeaders(map[string]string{
		"Content-Security-Policy": "script-src https:",
		"X-Frame-Options":         "DENY",
	}, "https://127.0.0.1/")
	if !findingHas(httpsScheme, "csp-wildcard-script") {
		t.Fatalf("https: scheme: %v", httpsScheme)
	}
	_, both := ExtractHeaders(map[string]string{
		"Content-Security-Policy": "script-src * 'unsafe-inline'",
		"X-Frame-Options":         "DENY",
	}, "https://127.0.0.1/")
	if !findingHas(both, "csp-wildcard-script") || !findingHas(both, "weak-csp") {
		t.Fatalf("wildcard+unsafe: %v", both)
	}
	_, overridden := ExtractHeaders(map[string]string{
		"Content-Security-Policy": "default-src *; script-src 'self'",
		"X-Frame-Options":         "DENY",
	}, "https://127.0.0.1/")
	if findingHas(overridden, "csp-wildcard-script") {
		t.Fatalf("script-src should override default-src *: %v", overridden)
	}
	_, host := ExtractHeaders(map[string]string{
		"Content-Security-Policy": "script-src *.example.com",
		"X-Frame-Options":         "DENY",
	}, "https://127.0.0.1/")
	if findingHas(host, "csp-wildcard-script") {
		t.Fatalf("*.example.com is not a token *: %v", host)
	}
	_, strict := ExtractHeaders(map[string]string{
		"Content-Security-Policy": "script-src 'self'",
		"X-Frame-Options":         "DENY",
	}, "https://127.0.0.1/")
	if findingHas(strict, "csp-wildcard-script") {
		t.Fatalf("strict script-src: %v", strict)
	}

	_, missingFA := ExtractHeaders(map[string]string{
		"Content-Security-Policy": "default-src 'self'",
	}, "https://127.0.0.1/")
	if !findingHas(missingFA, "csp-missing-frame-ancestors") {
		t.Fatalf("missing frame-ancestors: %v", missingFA)
	}
	_, withFA := ExtractHeaders(map[string]string{
		"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
	}, "https://127.0.0.1/")
	if findingHas(withFA, "csp-missing-frame-ancestors") {
		t.Fatalf("frame-ancestors present: %v", withFA)
	}
	_, withXFO := ExtractHeaders(map[string]string{
		"Content-Security-Policy": "default-src 'self'",
		"X-Frame-Options":         "DENY",
	}, "https://127.0.0.1/")
	if findingHas(withXFO, "csp-missing-frame-ancestors") {
		t.Fatalf("XFO present: %v", withXFO)
	}
	_, noCSP := ExtractHeaders(map[string]string{}, "https://127.0.0.1/")
	if findingHas(noCSP, "csp-missing-frame-ancestors") {
		t.Fatalf("no enforcing CSP should not emit csp-missing-frame-ancestors: %v", noCSP)
	}

	_, reportOnly := ExtractHeaders(map[string]string{
		"Content-Security-Policy-Report-Only": "default-src 'self'",
	}, "https://127.0.0.1/")
	if !findingHas(reportOnly, "csp-report-only") || !findingHas(reportOnly, "missing-csp") {
		t.Fatalf("report-only: %v", reportOnly)
	}
	_, enforcing := ExtractHeaders(map[string]string{
		"Content-Security-Policy":             "default-src 'self'",
		"Content-Security-Policy-Report-Only": "default-src 'none'",
		"X-Frame-Options":                     "DENY",
	}, "https://127.0.0.1/")
	if findingHas(enforcing, "csp-report-only") {
		t.Fatalf("enforcing CSP present: %v", enforcing)
	}
	_, none := ExtractHeaders(map[string]string{"X-Frame-Options": "DENY"}, "https://127.0.0.1/")
	if findingHas(none, "csp-report-only") {
		t.Fatalf("no report-only header: %v", none)
	}
}

func TestBackupSuffixesAreDataFiles(t *testing.T) {
	suffixes := LoadBackupSuffixes()
	if len(suffixes) == 0 {
		t.Skip("wordlists not found from cwd")
	}
	want := []string{".bak", ".old", ".orig", "~", ".swp", ".copy"}
	if len(suffixes) != len(want) {
		t.Fatalf("suffixes %v", suffixes)
	}
	for i, s := range want {
		if suffixes[i] != s {
			t.Fatalf("suffixes %v", suffixes)
		}
	}
	paths := LoadCommonPaths()
	have := map[string]bool{}
	for _, p := range paths {
		have[p] = true
	}
	if have["/.bak"] || have["/~"] || have[".bak"] {
		t.Fatalf("suffix wordlist leaked into common paths: %v", paths)
	}
	interesting := LoadBackupInteresting()
	if len(interesting) == 0 {
		t.Fatal("interesting names empty")
	}
	mutated := MutationPaths([]string{"/", "/login", "/settings", "/about", "/backup.sql.bak", "/static/app.js"})
	has := map[string]bool{}
	for _, p := range mutated {
		has[p] = true
	}
	for _, wantPath := range []string{"/login.bak", "/login.old", "/login~", "/settings.bak", "/backup.sql.bak.bak"} {
		if !has[wantPath] {
			t.Fatalf("missing mutation %s in %v", wantPath, mutated)
		}
	}
	for _, no := range []string{"/about.bak", "/static/app.js.bak", "/.bak"} {
		if has[no] {
			t.Fatalf("unexpected mutation %s", no)
		}
	}
}

func TestVerboseAndHoneypotStyle(t *testing.T) {
	fs := ExtractVerbose("Traceback (most recent call last)\nboom", "http://127.0.0.1/e", 500)
	if len(fs) == 0 {
		t.Fatal("verbose")
	}
}
