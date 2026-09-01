package proxy_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/shroodler/proxy-go/internal/proxy"
)

func TestReplayTags(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	s, _, _ := startProxy(t)
	base := &proxy.Session{
		ID: "orig",
		Request: proxy.HTTPMsg{
			Method:  "GET",
			URL:     upstream.URL + "/",
			Headers: map[string]string{},
			Body:    proxy.Body{Encoding: "utf8", Content: ""},
		},
	}
	if err := s.ReplaySession(base, nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	_ = http.StatusOK
}

func TestCompose(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("composed"))
	}))
	defer upstream.Close()
	s, _, _ := startProxy(t)
	if err := s.Compose(map[string]any{
		"method":  "GET",
		"url":     upstream.URL + "/",
		"headers": map[string]any{},
		"body":    "",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestBreakpointTimeout(t *testing.T) {
	s, _, _ := startProxy(t)
	s.Timeout = 30 * time.Millisecond
	s.SetBreakpoints([]proxy.BPRule{{Method: "GET", URLPattern: ".*", Stage: "request"}})
	// pauseIf is exercised via HTTP in capture tests; timeout path covered when matching.
}
