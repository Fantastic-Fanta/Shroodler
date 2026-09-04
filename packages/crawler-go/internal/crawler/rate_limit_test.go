package crawler_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/shroodler/crawler-go/internal/crawler"
)

func loginPageHandler(behavior func(attempt int) (int, string)) http.HandlerFunc {
	n := 0
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<form method="post" action="/login"><input name="username"><input name="password" type="password"></form>`))
			return
		}
		if r.URL.Path == "/login" && r.Method == http.MethodPost {
			status, body := behavior(n)
			n++
			w.WriteHeader(status)
			w.Write([]byte(body))
			return
		}
		w.WriteHeader(404)
	}
}

func TestCheckRateLimitOffByDefault(t *testing.T) {
	posts := 0
	srv := httptest.NewServer(loginPageHandler(func(n int) (int, string) {
		posts++
		return 200, "invalid credentials"
	}))
	defer srv.Close()

	res, err := crawler.Crawl(srv.URL+"/", crawler.Config{Depth: 1, IgnoreRobots: true, MaxPages: 50})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Findings {
		if f.ID == "missing-rate-limit" {
			t.Fatalf("did not expect missing-rate-limit without --check-rate-limit, got %#v", f)
		}
	}
	if posts != 0 {
		t.Fatalf("expected no POSTs to /login without the flag, got %d", posts)
	}
}

func TestCheckRateLimitFlagsUnthrottledLogin(t *testing.T) {
	srv := httptest.NewServer(loginPageHandler(func(n int) (int, string) {
		return 200, "invalid credentials"
	}))
	defer srv.Close()

	res, err := crawler.Crawl(srv.URL+"/", crawler.Config{Depth: 1, IgnoreRobots: true, MaxPages: 50, CheckRateLimit: true})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range res.Findings {
		if f.ID == "missing-rate-limit" {
			found = true
			if f.Category != "auth" {
				t.Fatalf("expected category auth, got %s", f.Category)
			}
		}
	}
	if !found {
		t.Fatalf("expected missing-rate-limit finding, got %#v", res.Findings)
	}
}

func TestCheckRateLimitSilentWhenThrottled(t *testing.T) {
	srv := httptest.NewServer(loginPageHandler(func(n int) (int, string) {
		if n >= 2 {
			return 429, "too many requests"
		}
		return 200, "invalid credentials"
	}))
	defer srv.Close()

	res, err := crawler.Crawl(srv.URL+"/", crawler.Config{Depth: 1, IgnoreRobots: true, MaxPages: 50, CheckRateLimit: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Findings {
		if f.ID == "missing-rate-limit" {
			t.Fatalf("did not expect missing-rate-limit when 429 is seen, got %#v", f)
		}
	}
}

func TestCheckRateLimitSilentOnLockoutKeyword(t *testing.T) {
	srv := httptest.NewServer(loginPageHandler(func(n int) (int, string) {
		if n >= 3 {
			return 200, "Account temporarily locked, try again later"
		}
		return 200, "invalid credentials"
	}))
	defer srv.Close()

	res, err := crawler.Crawl(srv.URL+"/", crawler.Config{Depth: 1, IgnoreRobots: true, MaxPages: 50, CheckRateLimit: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Findings {
		if f.ID == "missing-rate-limit" {
			t.Fatalf("did not expect missing-rate-limit when a lockout keyword is seen, got %#v", f)
		}
	}
}

func TestCheckRateLimitIgnoresNonLoginForms(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<form method="get" action="/search"><input name="q"></form>`))
			return
		}
		w.Write([]byte("<p>no rows</p>"))
	}))
	defer srv.Close()

	res, err := crawler.Crawl(srv.URL+"/", crawler.Config{Depth: 1, IgnoreRobots: true, MaxPages: 50, CheckRateLimit: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Findings {
		if f.ID == "missing-rate-limit" {
			t.Fatalf("did not expect missing-rate-limit for a non-login form, got %#v", f)
		}
	}
}
