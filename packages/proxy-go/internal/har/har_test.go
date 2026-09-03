package har

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shroodler/proxy-go/internal/proxy"
)

func sampleSession() proxy.Session {
	note := "lab"
	return proxy.Session{
		ID:         "abc123",
		StartedAt:  "2026-09-01T12:00:00Z",
		FinishedAt: "2026-09-01T12:00:00.412Z",
		ClientAddr: "127.0.0.1:54213",
		Request: proxy.HTTPMsg{
			Method:      "POST",
			URL:         "http://127.0.0.1:8081/login?next=/",
			HTTPVersion: "HTTP/1.1",
			Headers:     map[string]string{"Content-Type": "application/json"},
			Body:        proxy.Body{Encoding: "utf8", Content: `{"u":"a"}`},
		},
		Response: &proxy.HTTPMsg{
			StatusCode:  200,
			HTTPVersion: "HTTP/1.1",
			Headers:     map[string]string{"Content-Type": "text/plain"},
			Body:        proxy.Body{Encoding: "utf8", Content: "ok"},
		},
		Tags:  []string{"recorded"},
		Notes: &note,
	}
}

func TestRoundTripMethodURLStatus(t *testing.T) {
	sess := sampleSession()
	var jsonl bytes.Buffer
	if err := WriteJSONL(&jsonl, []proxy.Session{sess}); err != nil {
		t.Fatal(err)
	}
	var harBuf bytes.Buffer
	if err := WriteHAR(&harBuf, []proxy.Session{sess}); err != nil {
		t.Fatal(err)
	}
	back, err := ReadHAR(&harBuf)
	if err != nil {
		t.Fatal(err)
	}
	if len(back) != 1 {
		t.Fatalf("got %d sessions", len(back))
	}
	got := back[0]
	if got.Request.Method != "POST" {
		t.Fatalf("method %s", got.Request.Method)
	}
	if got.Request.URL != "http://127.0.0.1:8081/login?next=/" {
		t.Fatalf("url %s", got.Request.URL)
	}
	if got.Response == nil || got.Response.StatusCode != 200 {
		t.Fatalf("status %+v", got.Response)
	}
	if got.ID != "abc123" {
		t.Fatalf("id %s", got.ID)
	}
	if got.Request.Body.Content != `{"u":"a"}` {
		t.Fatalf("req body %s", got.Request.Body.Content)
	}
	if got.Response.Body.Content != "ok" {
		t.Fatalf("resp body %s", got.Response.Body.Content)
	}
}

func TestJSONLFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "sessions.jsonl")
	harPath := filepath.Join(dir, "out.har")
	out := filepath.Join(dir, "back.jsonl")
	sess := sampleSession()
	raw, _ := json.Marshal(sess)
	if err := os.WriteFile(in, append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ExportFile(in, harPath); err != nil {
		t.Fatal(err)
	}
	if err := ImportFile(harPath, out); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ReadJSONL(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d", len(got))
	}
	if got[0].Request.Method != "POST" || got[0].Request.URL != sess.Request.URL {
		t.Fatalf("%+v", got[0].Request)
	}
	if got[0].Response == nil || got[0].Response.StatusCode != 200 {
		t.Fatalf("status %+v", got[0].Response)
	}
}

func TestBase64BodyRoundTrip(t *testing.T) {
	sess := sampleSession()
	sess.Response.Body = proxy.Body{Encoding: "base64", Content: "AQID"}
	var buf bytes.Buffer
	if err := WriteHAR(&buf, []proxy.Session{sess}); err != nil {
		t.Fatal(err)
	}
	back, err := ReadHAR(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if back[0].Response.Body.Encoding != "base64" || back[0].Response.Body.Content != "AQID" {
		t.Fatalf("%+v", back[0].Response.Body)
	}
}

func TestNullResponseRoundTrip(t *testing.T) {
	sess := sampleSession()
	sess.Response = nil
	sess.Tags = []string{"dropped"}
	var buf bytes.Buffer
	if err := WriteHAR(&buf, []proxy.Session{sess}); err != nil {
		t.Fatal(err)
	}
	back, err := ReadHAR(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if back[0].Response != nil {
		t.Fatalf("expected null response, got %+v", back[0].Response)
	}
}

func TestBrowserHARExtrasIgnored(t *testing.T) {
	doc := `{
  "log": {
    "version": "1.2",
    "creator": {"name": "Firefox", "version": "1"},
    "browser": {"name": "Firefox", "version": "1"},
    "pages": [{"id": "page_1", "title": "x", "startedDateTime": "2026-09-01T12:00:00Z", "pageTimings": {}}],
    "entries": [{
      "pageref": "page_1",
      "startedDateTime": "2026-09-01T12:00:00.000Z",
      "time": 12,
      "request": {
        "method": "GET",
        "url": "http://127.0.0.1:8081/x?q=1",
        "httpVersion": "HTTP/1.1",
        "cookies": [{"name": "a", "value": "b"}],
        "headers": [{"name": "Host", "value": "127.0.0.1:8081"}],
        "queryString": [{"name": "q", "value": "1"}],
        "headersSize": 50,
        "bodySize": 0
      },
      "response": {
        "status": 204,
        "statusText": "No Content",
        "httpVersion": "HTTP/1.1",
        "cookies": [],
        "headers": [],
        "content": {"size": 0, "mimeType": "x-unknown"},
        "redirectURL": "",
        "headersSize": -1,
        "bodySize": 0
      },
      "cache": {},
      "timings": {"send": 0, "wait": 12, "receive": 0},
      "serverIPAddress": "127.0.0.1",
      "connection": "123",
      "_priority": "High",
      "_webSocketMessages": []
    }]
  }
}`
	got, err := ReadHAR(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d", len(got))
	}
	if got[0].Request.Method != "GET" || got[0].Request.URL != "http://127.0.0.1:8081/x?q=1" {
		t.Fatalf("%+v", got[0].Request)
	}
	if got[0].Response == nil || got[0].Response.StatusCode != 204 {
		t.Fatalf("status %+v", got[0].Response)
	}
}

func TestPostDataParamsFallback(t *testing.T) {
	doc := `{
  "log": {
    "version": "1.2",
    "creator": {"name": "x", "version": "1"},
    "entries": [{
      "startedDateTime": "2026-09-01T12:00:00Z",
      "time": 0,
      "request": {
        "method": "POST",
        "url": "http://127.0.0.1/form",
        "httpVersion": "HTTP/1.1",
        "cookies": [],
        "headers": [],
        "queryString": [],
        "postData": {
          "mimeType": "application/x-www-form-urlencoded",
          "params": [
            {"name": "a", "value": "1"},
            {"name": "file", "value": "", "fileName": "x.bin", "contentType": "application/octet-stream"}
          ]
        },
        "headersSize": -1,
        "bodySize": 0
      },
      "response": {
        "status": 201,
        "statusText": "Created",
        "httpVersion": "HTTP/1.1",
        "cookies": [],
        "headers": [],
        "content": {"size": 0, "mimeType": ""},
        "redirectURL": "",
        "headersSize": -1,
        "bodySize": 0
      },
      "cache": {},
      "timings": {"send": 0, "wait": 0, "receive": 0}
    }]
  }
}`
	got, err := ReadHAR(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Request.Body.Content != "a=1" {
		t.Fatalf("body %q", got[0].Request.Body.Content)
	}
	if got[0].Response.StatusCode != 201 {
		t.Fatalf("status %d", got[0].Response.StatusCode)
	}
}

func TestSkipEmptyEntries(t *testing.T) {
	doc := `{"log":{"version":"1.2","creator":{"name":"x","version":"1"},"entries":[{}]}}`
	got, err := ReadHAR(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestReadHARRejectsNonHAR(t *testing.T) {
	if _, err := ReadHAR(strings.NewReader(`{"not":"har"}`)); err == nil {
		t.Fatal("expected error")
	}
	if _, err := ReadHAR(strings.NewReader(`not json`)); err == nil {
		t.Fatal("expected error")
	}
}

func TestReadJSONLLineError(t *testing.T) {
	_, err := ReadJSONL(strings.NewReader("{\"id\":\"a\"}\nnot-json\n"))
	if err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("err %v", err)
	}
}

func TestDuplicateHeadersJoin(t *testing.T) {
	hs := []NameValue{{Name: "Accept", Value: "a"}, {Name: "Accept", Value: "b"}}
	m := headersToMap(hs)
	if m["Accept"] != "a, b" {
		t.Fatalf("%v", m)
	}
}
