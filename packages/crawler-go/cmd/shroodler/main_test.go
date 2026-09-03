package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shroodler/crawler-go/internal/crawler"
)

func TestCmdCrawlAndDiff(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>ok</body></html>`))
	}))
	defer srv.Close()
	dir := t.TempDir()
	out := filepath.Join(dir, "o.json")
	if cmdCrawl([]string{srv.URL + "/", "--depth", "0", "--output", out, "--mode", "static"}) != 0 {
		t.Fatal("crawl")
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatal(err)
	}
	exp := filepath.Join(dir, "e.json")
	os.WriteFile(exp, []byte(`{"expected_pages":["/"]}`), 0o644)
	if cmdDiff([]string{out, exp, "--pages-only"}) != 0 {
		t.Fatal("diff")
	}
	rep := filepath.Join(dir, "r.html")
	if cmdReport([]string{out, "--format", "html", "--output", rep}) != 0 {
		t.Fatal("report")
	}
	if cmdReport([]string{out, "--format", "csv"}) != 0 {
		t.Fatal("csv")
	}
	if cmdReport([]string{out, "--format", "sarif", "--output", filepath.Join(dir, "r.sarif")}) != 0 {
		t.Fatal("sarif")
	}
	if cmdBaseline([]string{out, "--name", "cli-app", "--output", filepath.Join(dir, "base.json")}) != 0 {
		t.Fatal("baseline")
	}
	if cmdDiff([]string{out, filepath.Join(dir, "base.json"), "--gate"}) != 0 {
		t.Fatal("gate")
	}
	jl := filepath.Join(dir, "s.jsonl")
	os.WriteFile(jl, []byte(`{"id":"1","started_at":"2026-09-01T00:00:00Z","request":{"method":"GET","url":"`+srv.URL+`/","headers":{}},"response":{"status_code":200,"headers":{"Content-Type":"text/html"},"body":{"encoding":"utf8","content":"<html>ok</html>"}}}
`), 0o644)
	ing := filepath.Join(dir, "ing.json")
	if cmdIngest([]string{jl, "--target", srv.URL, "--output", ing}) != 0 {
		t.Fatal("ingest")
	}
}

func TestCmdCrawlHeaderAndCookie(t *testing.T) {
	var gotHeader, gotCookie string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Lab-Auth")
		gotCookie = r.Header.Get("Cookie")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>ok</body></html>`))
	}))
	defer srv.Close()
	dir := t.TempDir()
	out := filepath.Join(dir, "o.json")
	code := cmdCrawl([]string{
		srv.URL + "/",
		"--depth", "0",
		"--ignore-robots",
		"--header", "X-Lab-Auth: open",
		"--cookie", "lab_auth=open",
		"--output", out,
	})
	if code != 0 {
		t.Fatal("crawl")
	}
	if gotHeader != "open" {
		t.Fatalf("header %q", gotHeader)
	}
	if !strings.Contains(gotCookie, "lab_auth=open") {
		t.Fatalf("cookie %q", gotCookie)
	}
}

func TestCmdCrawlRCHeaderCookie(t *testing.T) {
	var gotHeader, gotCookie string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Lab-Auth")
		gotCookie = r.Header.Get("Cookie")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>ok</body></html>`))
	}))
	defer srv.Close()
	dir := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".shroodlerrc"), []byte("header:\n  - \"X-Lab-Auth: open\"\ncookie:\n  - lab_auth=open\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(cwd) })
	out := filepath.Join(dir, "o.json")
	if cmdCrawl([]string{srv.URL + "/", "--depth", "0", "--ignore-robots", "--output", out}) != 0 {
		t.Fatal("crawl")
	}
	if gotHeader != "open" {
		t.Fatalf("rc header %q", gotHeader)
	}
	if !strings.Contains(gotCookie, "lab_auth=open") {
		t.Fatalf("rc cookie %q", gotCookie)
	}
}

func TestCmdCrawlHeadless(t *testing.T) {
	if cmdCrawl([]string{"http://127.0.0.1/", "--mode", "nope"}) != 2 {
		t.Fatal("invalid mode should be 2")
	}
	if crawler.HeadlessAvailable() {
		return
	}
	code := cmdCrawl([]string{"http://127.0.0.1/", "--mode", "headless", "--depth", "0"})
	if code != 1 {
		t.Fatalf("expected chrome-missing error, got %d", code)
	}
}

func TestCmdCrawlMissingArg(t *testing.T) {
	if cmdCrawl(nil) != 2 {
		t.Fatal()
	}
}

func TestRunUsage(t *testing.T) {
	if run(nil) != 2 {
		t.Fatal("empty")
	}
	if run([]string{"nope"}) != 2 {
		t.Fatal("unknown")
	}
}

func TestCmdPayloadRefuseAndMissing(t *testing.T) {
	if cmdPayload(nil) != 2 {
		t.Fatal("usage")
	}
	dir := t.TempDir()
	in := filepath.Join(dir, "c.json")
	os.WriteFile(in, []byte(`{"target":"https://example.com/","pages":[]}`), 0o644)
	if cmdPayload([]string{in}) != 1 {
		t.Fatal("expected refuse")
	}
}

func TestCmdExpected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><form action="/login" method="POST"><input name="username"><input name="password" type="password"></form></body></html>`))
	}))
	defer srv.Close()
	dir := t.TempDir()
	scan := filepath.Join(dir, "scan.json")
	if cmdCrawl([]string{srv.URL + "/", "--depth", "0", "--output", scan, "--mode", "static", "--ignore-robots"}) != 0 {
		t.Fatal("crawl")
	}
	exp := filepath.Join(dir, "expected_findings.json")
	if run([]string{"expected", scan, "--output", exp, "--name", "tiny"}) != 0 {
		t.Fatal("expected")
	}
	raw, err := os.ReadFile(exp)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if body["target_app"] != "tiny" {
		t.Fatalf("name %v", body["target_app"])
	}
	pages, _ := body["expected_pages"].([]any)
	if len(pages) < 1 {
		t.Fatalf("expected_pages %#v", pages)
	}
	if _, ok := body["expected_forms"].(map[string]any); !ok {
		t.Fatal("expected_forms")
	}
	if _, ok := body["expected_findings"].([]any); !ok {
		t.Fatal("expected_findings")
	}
	nf, _ := body["expected_not_found"].([]any)
	if len(nf) != 0 {
		t.Fatalf("invented negatives %#v", nf)
	}
}
