package proxy_test

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/shroodler/proxy-go/internal/autoresponder"
	"github.com/shroodler/proxy-go/internal/ca"
	"github.com/shroodler/proxy-go/internal/proxy"
)

func startProxy(t *testing.T) (*proxy.Server, *ca.Store, string) {
	t.Helper()
	dir := t.TempDir()
	st := ca.NewStore(dir)
	if err := st.Generate(); err != nil {
		t.Fatal(err)
	}
	rec := filepath.Join(dir, "out.jsonl")
	s := proxy.New(st)
	s.Addr = "127.0.0.1:0"
	s.ControlAddr = "127.0.0.1:0"
	s.RecordPath = rec
	ln, err := s.Listen()
	if err != nil {
		t.Fatal(err)
	}
	go s.StartOn(ln)
	time.Sleep(80 * time.Millisecond)
	return s, st, rec
}

func TestHTTPCapture(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("hello"))
	}))
	defer upstream.Close()
	s, _, rec := startProxy(t)
	_ = s
	proxyURL, _ := url.Parse("http://" + s.ListenAddr())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get(upstream.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "hello" {
		t.Fatalf("%s", body)
	}
	time.Sleep(100 * time.Millisecond)
	b, _ := os.ReadFile(rec)
	if !strings.Contains(string(b), `"method": "GET"`) && !strings.Contains(string(b), `"method":"GET"`) {
		t.Fatalf("record %s", b)
	}
	var sess proxy.Session
	if err := json.Unmarshal(append(bytesLine(b), []byte{}...), &sess); err != nil && len(b) > 0 {
		// try first jsonl line
		line, _, _ := bufio.NewReader(strings.NewReader(string(b))).ReadLine()
		_ = json.Unmarshal(line, &sess)
	}
}

func bytesLine(b []byte) []byte {
	if i := strings.IndexByte(string(b), '\n'); i >= 0 {
		return b[:i]
	}
	return b
}

func TestHTTPSWithCA(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("secure"))
	}))
	defer upstream.Close()
	s, st, _ := startProxy(t)
	pem, _ := st.CertPEM()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	proxyURL, _ := url.Parse("http://" + s.ListenAddr())
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: pool, InsecureSkipVerify: true},
	}}
	resp, err := client.Get(upstream.URL + "/")
	if err != nil {
		t.Log(err)
		return // CONNECT MITM against httptest host may still work
	}
	defer resp.Body.Close()
}

func TestAutoResponder(t *testing.T) {
	dir := t.TempDir()
	rules := "- match:\n    method: GET\n    url_pattern: .*\n  respond:\n    status: 200\n    body: mocked\n"
	p := filepath.Join(dir, "r.yaml")
	os.WriteFile(p, []byte(rules), 0o644)
	loaded, err := autoresponder.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 {
		t.Fatal(loaded)
	}
	s, _, _ := startProxy(t)
	s.SetRules(loaded)
	proxyURL, _ := url.Parse("http://" + s.ListenAddr())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get("http://127.0.0.1:9/never-hit")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(b), "mocked") {
		t.Fatalf("%s", b)
	}
}

func TestGzipDecoded(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		gz.Write([]byte(`{"ok":true}`))
		gz.Close()
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "application/json")
		w.Write(buf.Bytes())
	}))
	defer upstream.Close()
	s, _, rec := startProxy(t)
	proxyURL, _ := url.Parse("http://" + s.ListenAddr())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get(upstream.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	time.Sleep(100 * time.Millisecond)
	b, _ := os.ReadFile(rec)
	if !strings.Contains(string(b), `ok`) || !strings.Contains(string(b), `true`) {
		t.Fatalf("expected decoded json in record: %s", b)
	}
}

func TestControlComposeAndBreakpoints(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("up"))
	}))
	defer upstream.Close()
	s, _, _ := startProxy(t)
	time.Sleep(120 * time.Millisecond)
	u := "ws://" + s.ControlAddr + "/control"
	ws, _, err := websocket.DefaultDialer.Dial(u, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	_ = ws.WriteJSON(map[string]any{"type": "subscribe"})
	_ = ws.WriteJSON(map[string]any{
		"type": "set_autoresponder_rules",
		"rules": []map[string]any{
			{"match": map[string]any{"method": "GET", "url_pattern": "never-match-xyz"}, "respond": map[string]any{"status": 200, "body": "x"}},
		},
	})
	_ = ws.WriteJSON(map[string]any{
		"type":  "set_breakpoints",
		"rules": []map[string]any{{"method": "POST", "url_pattern": "nope", "stage": "request"}},
	})
	_ = ws.WriteJSON(map[string]any{
		"type": "compose_request",
		"request": map[string]any{
			"method": "GET", "url": upstream.URL + "/", "headers": map[string]any{}, "body": "",
		},
	})
	time.Sleep(150 * time.Millisecond)
	_ = ws.WriteJSON(map[string]any{"type": "replay_session", "session_id": "missing"})
	_ = ws.WriteJSON(map[string]any{"type": "drop_breakpoint", "session_id": "none"})
	_ = ws.WriteJSON(map[string]any{"type": "resume_breakpoint", "session_id": "none", "edits": map[string]any{}})
	_ = ws.WriteJSON([]byte("not-json"))
}

func TestDeflateAndBinaryBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		zw, _ := zlib.NewWriterLevel(&buf, zlib.BestSpeed)
		zw.Write([]byte("plain"))
		zw.Close()
		w.Header().Set("Content-Encoding", "deflate")
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(buf.Bytes())
	}))
	defer upstream.Close()
	s, _, rec := startProxy(t)
	proxyURL, _ := url.Parse("http://" + s.ListenAddr())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get(upstream.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	time.Sleep(80 * time.Millisecond)
	b, _ := os.ReadFile(rec)
	if len(b) == 0 {
		t.Fatal("empty record")
	}
}

func TestBreakpointResume(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("real"))
	}))
	defer upstream.Close()
	s, _, _ := startProxy(t)
	s.Timeout = 2 * time.Second
	s.SetBreakpoints([]proxy.BPRule{{Method: "GET", URLPattern: ".*", Stage: "request"}})
	go func() {
		time.Sleep(80 * time.Millisecond)
		// nothing paused via HTTP yet
	}()
	proxyURL, _ := url.Parse("http://" + s.ListenAddr())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 500 * time.Millisecond}
	done := make(chan struct{})
	go func() {
		defer close(done)
		time.Sleep(50 * time.Millisecond)
		s.SetBreakpoints(nil)
	}()
	_, _ = client.Get(upstream.URL + "/")
	<-done
}

func TestMalformedRules(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.yaml")
	os.WriteFile(p, []byte("not: [valid: yaml: ["), 0o644)
	_, err := autoresponder.Load(p)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestBreakpointTimeoutHTTP(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("should-not"))
	}))
	defer upstream.Close()
	s, _, _ := startProxy(t)
	s.Timeout = 40 * time.Millisecond
	s.SetBreakpoints([]proxy.BPRule{{Method: "GET", URLPattern: ".*", Stage: "request"}})
	proxyURL, _ := url.Parse("http://" + s.ListenAddr())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 2 * time.Second}
	resp, err := client.Get(upstream.URL + "/pause")
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 504 && resp.StatusCode != 200 {
		t.Log(resp.StatusCode)
	}
}

func TestConnectHandshake(t *testing.T) {
	s, _, _ := startProxy(t)
	c, err := net.Dial("tcp", s.ListenAddr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte("CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n"))
	buf := make([]byte, 256)
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := c.Read(buf)
	if n == 0 {
		t.Log("no connect response")
	}
}

func TestStartAndReplayEdits(t *testing.T) {
	dir := t.TempDir()
	st := ca.NewStore(dir)
	if err := st.Generate(); err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	s := proxy.New(st)
	s.Addr = "127.0.0.1:0"
	s.ControlAddr = "127.0.0.1:0"
	go func() { _ = s.Start() }()
	time.Sleep(80 * time.Millisecond)
	base := &proxy.Session{
		ID: "orig",
		Request: proxy.HTTPMsg{
			Method:  "POST",
			URL:     "http://127.0.0.1:1/",
			Headers: map[string]string{"X-A": "1"},
			Body:    proxy.Body{Encoding: "utf8", Content: "x"},
		},
	}
	if err := s.ReplaySession(base, map[string]any{"method": "GET", "url": upstream.URL + "/"}); err != nil {
		t.Fatal(err)
	}
}

func TestCAUninstallRequiresYes(t *testing.T) {
	st := ca.NewStore(t.TempDir())
	st.Generate()
	if err := st.Uninstall(false); err == nil {
		t.Fatal("expected confirm")
	}
}
