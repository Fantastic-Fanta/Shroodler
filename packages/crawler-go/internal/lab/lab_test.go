package lab

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

func sampleDoc() map[string]any {
	raw := `{
	  "target": "http://127.0.0.1:8081",
	  "crawler": {"name": "shroodler-go", "version": "0.1.0", "mode": "static"},
	  "pages": [
	    {"url": "http://127.0.0.1:8081/", "status_code": 200, "forms": [], "params": [], "cookies": [], "headers": {"present": [], "missing": []}, "js_files": []},
	    {"url": "http://127.0.0.1:8081/login", "status_code": 200, "forms": [{"action": "/login", "method": "POST", "fields": [{"name": "username", "type": "text", "hidden": false}, {"name": "password", "type": "password", "hidden": false}]}], "params": [], "cookies": [], "headers": {"present": [], "missing": []}, "js_files": []}
	  ],
	  "findings": [
	    {"id": "missing-csp", "severity": "medium", "category": "header", "url": "http://127.0.0.1:8081/login", "description": "CSP missing"},
	    {"id": "server-version-leak", "severity": "info", "category": "header", "url": "http://127.0.0.1:8081/", "description": "Server header"}
	  ]
	}`
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		panic(err)
	}
	return m
}

func TestBaselineFromScan(t *testing.T) {
	base := BaselineFromDoc(sampleDoc(), "lab-app", nil)
	pages, _ := base["expected_pages"].([]any)
	if len(pages) != 2 || fmt.Sprint(pages[0]) != "/" || fmt.Sprint(pages[1]) != "/login" {
		t.Fatalf("pages %#v", pages)
	}
	forms := base["expected_forms"].(map[string]any)
	login, _ := forms["/login"].([]any)
	joined := fmt.Sprint(login)
	if !strings.Contains(joined, "password") || !strings.Contains(joined, "username") {
		t.Fatalf("forms %#v", login)
	}
	findings := base["expected_findings"].([]any)
	if len(findings) != 2 {
		t.Fatalf("findings %d", len(findings))
	}
	out := Diff(sampleDoc(), base, false, false, nil)
	if len(out.Errors) != 0 {
		t.Fatalf("fixture diff %v", out.Errors)
	}
	nf, ok := base["expected_not_found"].([]any)
	if !ok || len(nf) != 0 {
		t.Fatalf("generator must not invent expected_not_found: %#v", base["expected_not_found"])
	}
}

func TestBaselineOmitsSuppressions(t *testing.T) {
	rules := ParseSuppressions("suppressions:\n  - id: server-version-leak\n    url: '*'\n    reason: noise\n")
	base := BaselineFromDoc(sampleDoc(), "lab-app", rules)
	findings := base["expected_findings"].([]any)
	if len(findings) != 1 {
		t.Fatalf("got %d", len(findings))
	}
	m := findings[0].(map[string]any)
	if m["id"] != "missing-csp" {
		t.Fatalf("%v", m)
	}
}

func TestGateNewAndResolved(t *testing.T) {
	base := BaselineFromDoc(sampleDoc(), "lab-app", nil)
	extra := sampleDoc()
	findings := extra["findings"].([]any)
	findings = append(findings, map[string]any{
		"id": "exposed-file", "severity": "high", "category": "exposed-file",
		"url": "http://127.0.0.1:8081/.env", "description": "env",
	})
	extra["findings"] = findings
	out := Diff(extra, base, false, true, nil)
	if len(out.Errors) != 1 || !strings.Contains(out.Errors[0], "new finding exposed-file") {
		t.Fatalf("gate extra %v", out.Errors)
	}
	gone := sampleDoc()
	gone["findings"] = []any{gone["findings"].([]any)[1]}
	resolved := Diff(gone, base, false, true, nil)
	if len(resolved.Errors) != 0 {
		t.Fatalf("resolved should not fail: %v", resolved.Errors)
	}
	if len(resolved.Resolved) == 0 {
		t.Fatal("expected resolved note")
	}
	fixture := Diff(gone, base, false, false, nil)
	if len(fixture.Errors) == 0 {
		t.Fatal("fixture mode should fail")
	}
}

func TestGateSuppressions(t *testing.T) {
	base := BaselineFromDoc(sampleDoc(), "lab-app", nil)
	extra := sampleDoc()
	findings := extra["findings"].([]any)
	findings = append(findings, map[string]any{
		"id": "missing-csp", "severity": "medium", "category": "header",
		"url": "http://127.0.0.1:8081/static/x.js", "description": "csp",
	})
	extra["findings"] = findings
	rules := ParseSuppressions("suppressions:\n  - id: missing-csp\n    url: /static/*\n    reason: assets\n")
	if errs := Diff(extra, base, false, true, rules).Errors; len(errs) != 0 {
		t.Fatalf("suppressed extra should pass: %v", errs)
	}
	if errs := Diff(extra, base, false, true, nil).Errors; len(errs) == 0 {
		t.Fatal("unsuppressed extra should fail")
	}
}

func TestSARIFAndJUnit(t *testing.T) {
	sarifRaw := RenderSARIF(sampleDoc())
	var sarif map[string]any
	if err := json.Unmarshal([]byte(sarifRaw), &sarif); err != nil {
		t.Fatal(err)
	}
	if sarif["version"] != "2.1.0" {
		t.Fatalf("version %v", sarif["version"])
	}
	runs := sarif["runs"].([]any)
	run := runs[0].(map[string]any)
	results := run["results"].([]any)
	if len(results) != 2 {
		t.Fatalf("results %d", len(results))
	}
	level := results[0].(map[string]any)["level"]
	if level != "warning" && level != "note" {
		t.Fatalf("level %v", level)
	}
	junit := RenderJUnit(sampleDoc())
	if !strings.Contains(junit, `failures="2"`) || !strings.Contains(junit, "<testsuite") {
		t.Fatalf("junit %s", junit)
	}
	empty := RenderJUnit(map[string]any{"findings": []any{}})
	if !strings.Contains(empty, `failures="0"`) {
		t.Fatalf("empty %s", empty)
	}
}

func TestLoadSuppressionsMissing(t *testing.T) {
	dir := t.TempDir()
	wd, _ := os.Getwd()
	defer os.Chdir(wd)
	os.Chdir(dir)
	if rules := LoadSuppressions(""); len(rules) != 0 {
		t.Fatalf("%v", rules)
	}
}

func TestGlobMatch(t *testing.T) {
	if !GlobMatch("/static/*", "/static/app.js") {
		t.Fatal("star")
	}
	if GlobMatch("/login", "/settings") {
		t.Fatal("no match")
	}
}
