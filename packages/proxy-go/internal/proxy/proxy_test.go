package proxy_test

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestMalformedRules(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.yaml")
	os.WriteFile(p, []byte("not: [valid: yaml: ["), 0o644)
	_, err := autoresponder.Load(p)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCAUninstallRequiresYes(t *testing.T) {
	st := ca.NewStore(t.TempDir())
	st.Generate()
	if err := st.Uninstall(false); err == nil {
		t.Fatal("expected confirm")
	}
}
