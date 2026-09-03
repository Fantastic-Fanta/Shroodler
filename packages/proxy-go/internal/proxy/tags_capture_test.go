package proxy_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/shroodler/proxy-go/internal/proxy"
)

func waitRecorded(t *testing.T, rec string) proxy.Session {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		b, _ := os.ReadFile(rec)
		line := bytesLine(b)
		if len(line) > 0 {
			var sess proxy.Session
			if json.Unmarshal(line, &sess) == nil && sess.ID != "" {
				return sess
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no session recorded")
	return proxy.Session{}
}

func proxyClient(t *testing.T, s *proxy.Server) *http.Client {
	t.Helper()
	proxyURL, err := url.Parse("http://" + s.ListenAddr())
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func TestCaptureTagsJSONAnd2xx(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()
	s, _, rec := startProxy(t)
	resp, err := proxyClient(t, s).Get(upstream.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	sess := waitRecorded(t, rec)
	for _, tag := range []string{"json", "2xx"} {
		if !slices.Contains(sess.Tags, tag) {
			t.Fatalf("missing %s in %v record", tag, sess.Tags)
		}
	}
}

func TestCaptureTagsStatusClasses(t *testing.T) {
	cases := []struct {
		code int
		tag  string
	}{
		{301, "3xx"},
		{404, "4xx"},
		{503, "5xx"},
	}
	for _, tc := range cases {
		t.Run(tc.tag, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.code)
				w.Write([]byte("x"))
			}))
			defer upstream.Close()
			s, _, rec := startProxy(t)
			resp, err := proxyClient(t, s).Get(upstream.URL + "/")
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			sess := waitRecorded(t, rec)
			if !slices.Contains(sess.Tags, tc.tag) {
				t.Fatalf("missing %s in %v", tc.tag, sess.Tags)
			}
		})
	}
}

func TestCaptureTagsSetCookie(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "sid=abc; Path=/")
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	s, _, rec := startProxy(t)
	resp, err := proxyClient(t, s).Get(upstream.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	sess := waitRecorded(t, rec)
	if !slices.Contains(sess.Tags, "set-cookie") {
		t.Fatalf("%v", sess.Tags)
	}
}

func TestCaptureTagsGraphQLPath(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":{}}`))
	}))
	defer upstream.Close()
	s, _, rec := startProxy(t)
	resp, err := proxyClient(t, s).Get(upstream.URL + "/graphql")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	sess := waitRecorded(t, rec)
	if !slices.Contains(sess.Tags, "graphql") {
		t.Fatalf("%v url=%s", sess.Tags, sess.Request.URL)
	}
}

func TestCaptureTagsGraphQLBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":{"ping":true}}`))
	}))
	defer upstream.Close()
	s, _, rec := startProxy(t)
	req, _ := http.NewRequest(http.MethodPost, upstream.URL+"/api", strings.NewReader(`{"query":"{ ping }"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := proxyClient(t, s).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	sess := waitRecorded(t, rec)
	for _, tag := range []string{"graphql", "json", "2xx"} {
		if !slices.Contains(sess.Tags, tag) {
			t.Fatalf("missing %s in %v", tag, sess.Tags)
		}
	}
}

func TestCaptureTagsNoResponse(t *testing.T) {
	s, _, rec := startProxy(t)
	s.Timeout = 40 * time.Millisecond
	s.SetBreakpoints([]proxy.BPRule{{Method: "GET", URLPattern: ".*", Stage: "request"}})
	resp, err := proxyClient(t, s).Get("http://127.0.0.1:9/pause")
	if err == nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	sess := waitRecorded(t, rec)
	for _, tag := range []string{"dropped", "breakpoint_timeout", "no-response"} {
		if !slices.Contains(sess.Tags, tag) {
			t.Fatalf("missing %s in %v", tag, sess.Tags)
		}
	}
}

func TestCaptureTagsKeepAutoResponder(t *testing.T) {
	s, _, rec := startProxy(t)
	rule := proxy.AutoRule{}
	rule.Match.Method = "GET"
	rule.Match.URLPattern = ".*"
	rule.Respond.Status = 201
	rule.Respond.Headers = map[string]string{"Content-Type": "application/json"}
	rule.Respond.BodyBytes = []byte(`{"mocked":true}`)
	s.SetRules([]proxy.AutoRule{rule})
	resp, err := proxyClient(t, s).Get("http://127.0.0.1:9/never")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	sess := waitRecorded(t, rec)
	for _, tag := range []string{"autoresponded", "json", "2xx"} {
		if !slices.Contains(sess.Tags, tag) {
			t.Fatalf("missing %s in %v", tag, sess.Tags)
		}
	}
}

func TestSessionCompleteIncludesTags(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "a=1")
		w.Write([]byte(`{"ok":1}`))
	}))
	defer upstream.Close()
	s, _, _ := startProxy(t)
	var last error
	var ws *websocket.Conn
	for i := 0; i < 25; i++ {
		time.Sleep(40 * time.Millisecond)
		if s.ControlAddr == "" || strings.HasSuffix(s.ControlAddr, ":0") {
			continue
		}
		ws, _, last = websocket.DefaultDialer.Dial("ws://"+s.ControlAddr+"/control", nil)
		if last == nil {
			break
		}
	}
	if ws == nil {
		t.Fatalf("control dial: %v", last)
	}
	defer ws.Close()
	_ = ws.WriteJSON(map[string]any{"type": "subscribe"})
	time.Sleep(50 * time.Millisecond)
	done := make(chan proxy.Session, 1)
	go func() {
		ws.SetReadDeadline(time.Now().Add(5 * time.Second))
		for {
			var msg map[string]any
			if err := ws.ReadJSON(&msg); err != nil {
				return
			}
			if msg["type"] != "session:complete" {
				continue
			}
			raw, _ := json.Marshal(msg["session"])
			var sess proxy.Session
			if json.Unmarshal(raw, &sess) == nil {
				done <- sess
				return
			}
		}
	}()
	resp, err := proxyClient(t, s).Get(upstream.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	select {
	case sess := <-done:
		for _, tag := range []string{"json", "2xx", "set-cookie"} {
			if !slices.Contains(sess.Tags, tag) {
				t.Fatalf("session:complete missing %s in %v", tag, sess.Tags)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no session:complete")
	}
}

func TestReplayKeepsReplayedFromTag(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()
	s, _, rec := startProxy(t)
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
	sess := waitRecorded(t, rec)
	if !slices.Contains(sess.Tags, "replayed_from:orig") {
		t.Fatalf("%v", sess.Tags)
	}
	if !slices.Contains(sess.Tags, "json") || !slices.Contains(sess.Tags, "2xx") {
		t.Fatalf("auto-tags missing: %v", sess.Tags)
	}
}
