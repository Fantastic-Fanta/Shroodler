package crawler_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/shroodler/crawler-go/internal/crawler"
	"github.com/shroodler/crawler-go/internal/sessions"
)

func writeJSONL(t *testing.T, sessions []map[string]any) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "s.jsonl")
	var b strings.Builder
	for _, s := range sessions {
		raw, _ := json.Marshal(s)
		b.Write(raw)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func sess(u string, headers map[string]string, body string) map[string]any {
	if headers == nil {
		headers = map[string]string{"Content-Type": "text/html"}
	}
	return map[string]any{
		"id":         "1",
		"started_at": "2026-09-01T00:00:00Z",
		"request":    map[string]any{"method": "GET", "url": u, "headers": map[string]string{}},
		"response": map[string]any{
			"status_code": 200,
			"headers":     headers,
			"body":        map[string]any{"encoding": "utf8", "content": body},
		},
	}
}

func TestCrawlThroughProxy(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html>ok</html>"))
	}))
	defer origin.Close()
	var hits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		out := r.Clone(r.Context())
		out.RequestURI = ""
		resp, err := http.DefaultTransport.RoundTrip(out)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		defer resp.Body.Close()
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}))
	defer proxy.Close()
	res, err := crawler.Crawl(origin.URL+"/", crawler.Config{Depth: 0, IgnoreRobots: true, Proxy: proxy.URL, MaxPages: 10})
	if err != nil {
		t.Fatal(err)
	}
	if hits.Load() < 1 {
		t.Fatal("proxy not used")
	}
	if len(res.Pages) == 0 || res.Pages[0].StatusCode != 200 {
		t.Fatalf("pages %+v", res.Pages)
	}
}

func TestSeedUnlinked(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("home")) })
	mux.HandleFunc("/hidden", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("hid")) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	res, err := crawler.Crawl(srv.URL+"/", crawler.Config{Depth: 0, IgnoreRobots: true, Seeds: []string{srv.URL + "/hidden"}, MaxPages: 20})
	if err != nil {
		t.Fatal(err)
	}
	var hid bool
	for _, p := range res.Pages {
		if strings.Contains(p.URL, "/hidden") {
			hid = true
		}
	}
	if !hid {
		t.Fatal("seed not crawled")
	}
}

func TestCookieHandoff(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Cookie")
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	_, err := crawler.Crawl(srv.URL+"/", crawler.Config{
		Depth: 0, IgnoreRobots: true,
		Cookies: []crawler.SeedCookie{{Name: "sid", Value: "from-proxy", Path: "/"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "sid=from-proxy") {
		t.Fatalf("cookie %q", got)
	}
}

func TestIngestSessions(t *testing.T) {
	u := "http://127.0.0.1:9/login"
	p := writeJSONL(t, []map[string]any{
		sess(u, map[string]string{"Content-Type": "text/html", "Set-Cookie": "sid=abc; HttpOnly"},
			`<form action="/login" method="post"><input name="username"></form>`),
	})
	res, err := crawler.Ingest(p, "http://127.0.0.1:9", false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Crawler.Mode != "ingest" {
		t.Fatal(res.Crawler.Mode)
	}
	if len(res.Pages) == 0 {
		t.Fatal("no pages")
	}
	found := false
	for _, f := range res.Findings {
		if f.ID == "insecure-cookie" {
			found = true
		}
	}
	if !found {
		t.Fatalf("findings %+v", res.Findings)
	}
}

func TestIngestRequestSecretAndNull(t *testing.T) {
	p := writeJSONL(t, []map[string]any{
		{
			"id": "1", "started_at": "2026-09-01T00:00:00Z",
			"request": map[string]any{
				"method": "POST", "url": "http://127.0.0.1:9/api",
				"headers": map[string]string{},
				"body":    map[string]any{"encoding": "utf8", "content": "token=AKIAIOSFODNN7EXAMPLE"},
			},
			"response": map[string]any{
				"status_code": 200,
				"headers":     map[string]string{"Content-Type": "application/json"},
				"body":        map[string]any{"encoding": "utf8", "content": "{}"},
			},
		},
		{
			"id": "2", "started_at": "2026-09-01T00:00:00Z",
			"request":  map[string]any{"method": "GET", "url": "http://127.0.0.1:9/gone", "headers": map[string]string{}},
			"response": nil,
		},
	})
	res, err := crawler.Ingest(p, "http://127.0.0.1:9", false)
	if err != nil {
		t.Fatal(err)
	}
	secret := false
	for _, f := range res.Findings {
		if f.Category == "secret" {
			secret = true
		}
	}
	if !secret {
		t.Fatal("expected secret from POST body")
	}
	for _, pg := range res.Pages {
		if strings.Contains(pg.URL, "/gone") {
			t.Fatal("null response ingested")
		}
	}
}

func TestCookiesSeedsOriginFilter(t *testing.T) {
	p := writeJSONL(t, []map[string]any{
		sess("http://127.0.0.1:8081/login", map[string]string{"Set-Cookie": "sid=one"}, "a"),
		sess("http://127.0.0.1:8081/login", map[string]string{"Set-Cookie": "sid=two"}, "a2"),
		sess("http://127.0.0.1:8082/other", map[string]string{"Set-Cookie": "other=x"}, "b"),
	})
	list, err := sessions.LoadJSONL(p)
	if err != nil {
		t.Fatal(err)
	}
	hdr := sessions.CookieHeader(list, "http://127.0.0.1:8081/")
	if !strings.Contains(hdr, "sid=two") || strings.Contains(hdr, "other=") {
		t.Fatalf("hdr %s", hdr)
	}
	seeds := sessions.SeedURLs(list, "http://127.0.0.1:8081/")
	for _, s := range seeds {
		u, _ := url.Parse(s)
		if u.Port() == "8082" {
			t.Fatal(s)
		}
	}
}
