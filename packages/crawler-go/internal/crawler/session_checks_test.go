package crawler

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/shroodler/crawler-go/internal/extractors"
)

func TestCheckSessionFixationFlagsUnchangedValue(t *testing.T) {
	findings := checkSessionFixation(
		map[string]string{"sessionid": "same-value"},
		map[string]string{"sessionid": "same-value"},
		"http://127.0.0.1/",
	)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %#v", findings)
	}
	if findings[0].ID != "session-fixation" || findings[0].Category != "auth" {
		t.Fatalf("unexpected finding %#v", findings[0])
	}
}

func TestCheckSessionFixationSilentWhenRegenerated(t *testing.T) {
	findings := checkSessionFixation(
		map[string]string{"sessionid": "old-value"},
		map[string]string{"sessionid": "new-value"},
		"http://127.0.0.1/",
	)
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %#v", findings)
	}
}

func TestCheckSessionFixationIgnoresEmptyPreValue(t *testing.T) {
	findings := checkSessionFixation(
		map[string]string{"sessionid": ""},
		map[string]string{"sessionid": ""},
		"http://127.0.0.1/",
	)
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %#v", findings)
	}
}

func TestCheckSessionFixationNoPreCookiesNoFindings(t *testing.T) {
	findings := checkSessionFixation(
		map[string]string{},
		map[string]string{"sessionid": "new"},
		"http://127.0.0.1/",
	)
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %#v", findings)
	}
}

func TestCheckLogoutInvalidationNoStaleCookieReturnsEmpty(t *testing.T) {
	findings := checkLogoutInvalidation(
		"http://127.0.0.1/logout", "GET", "http://127.0.0.1/account", "", 8*time.Second,
	)
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %#v", findings)
	}
}

func TestCheckLogoutInvalidationFlagsStillAccessible(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("secret account page"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	findings := checkLogoutInvalidation(
		srv.URL+"/logout", "GET", srv.URL+"/account", "sessionid=stale-value", 8*time.Second,
	)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %#v", findings)
	}
	if findings[0].ID != "logout-session-not-invalidated" || findings[0].Category != "auth" {
		t.Fatalf("unexpected finding %#v", findings[0])
	}
}

func TestCheckLogoutInvalidationSilentWhenDenied(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	findings := checkLogoutInvalidation(
		srv.URL+"/logout", "GET", srv.URL+"/account", "sessionid=stale-value", 8*time.Second,
	)
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %#v", findings)
	}
}

func TestExtractorsIsSessionCookieExported(t *testing.T) {
	// Sanity check that extractors.IsSessionCookie (renamed from an
	// unexported isSessionCookie as part of this port) is reachable and
	// still recognizes session-shaped names.
	if !extractors.IsSessionCookie("sessionid") {
		t.Fatal("expected sessionid to be recognized as a session cookie")
	}
	if extractors.IsSessionCookie("theme") {
		t.Fatal("theme should not be recognized as a session cookie")
	}
}
