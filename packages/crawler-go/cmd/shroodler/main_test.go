package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
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
}

func TestCmdCrawlHeadlessRejected(t *testing.T) {
	if cmdCrawl([]string{"http://127.0.0.1/", "--mode", "headless"}) != 2 {
		t.Fatal("expected 2")
	}
}

func TestCmdCrawlMissingArg(t *testing.T) {
	if cmdCrawl(nil) != 2 {
		t.Fatal()
	}
}
