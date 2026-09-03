package proxy

import (
	"encoding/base64"
	"slices"
	"strconv"
	"testing"
)

func TestAutoTagsJSON(t *testing.T) {
	cases := []struct {
		name     string
		reqCT    string
		respCT   string
		wantJSON bool
	}{
		{"response application/json", "", "application/json", true},
		{"response with charset", "", "application/json; charset=utf-8", true},
		{"response +json", "", "application/vnd.api+json", true},
		{"request json only", "application/json", "text/plain", true},
		{"text/json", "", "text/json", true},
		{"plain", "", "text/plain", false},
		{"empty", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reqH := map[string]string{}
			if tc.reqCT != "" {
				reqH["Content-Type"] = tc.reqCT
			}
			respH := map[string]string{}
			if tc.respCT != "" {
				respH["Content-Type"] = tc.respCT
			}
			sess := &Session{
				Request:  HTTPMsg{URL: "http://example.local/", Headers: reqH},
				Response: &HTTPMsg{StatusCode: 200, Headers: respH},
			}
			got := slices.Contains(autoTags(sess), "json")
			if got != tc.wantJSON {
				t.Fatalf("json tag=%v want %v tags=%v", got, tc.wantJSON, autoTags(sess))
			}
		})
	}
}

func TestAutoTagsStatusClass(t *testing.T) {
	cases := []struct {
		code int
		tag  string
	}{
		{200, "2xx"},
		{201, "2xx"},
		{301, "3xx"},
		{302, "3xx"},
		{404, "4xx"},
		{401, "4xx"},
		{500, "5xx"},
		{503, "5xx"},
	}
	for _, tc := range cases {
		t.Run(tc.tag+"/"+strconv.Itoa(tc.code), func(t *testing.T) {
			sess := &Session{
				Request:  HTTPMsg{URL: "http://example.local/", Headers: map[string]string{}},
				Response: &HTTPMsg{StatusCode: tc.code, Headers: map[string]string{}},
			}
			tags := autoTags(sess)
			if !slices.Contains(tags, tc.tag) {
				t.Fatalf("missing %s: %v", tc.tag, tags)
			}
			for _, other := range []string{"2xx", "3xx", "4xx", "5xx", "no-response"} {
				if other != tc.tag && slices.Contains(tags, other) {
					t.Fatalf("unexpected %s in %v", other, tags)
				}
			}
		})
	}
}

func TestAutoTagsNoResponse(t *testing.T) {
	sess := &Session{
		Request:  HTTPMsg{URL: "http://example.local/", Headers: map[string]string{}},
		Response: nil,
	}
	tags := autoTags(sess)
	if !slices.Contains(tags, "no-response") {
		t.Fatalf("%v", tags)
	}
	for _, s := range []string{"2xx", "3xx", "4xx", "5xx", "set-cookie"} {
		if slices.Contains(tags, s) {
			t.Fatalf("unexpected %s in %v", s, tags)
		}
	}
}

func TestAutoTagsSetCookie(t *testing.T) {
	with := &Session{
		Request:  HTTPMsg{URL: "http://example.local/", Headers: map[string]string{}},
		Response: &HTTPMsg{StatusCode: 200, Headers: map[string]string{"Set-Cookie": "sid=1; Path=/"}},
	}
	if !slices.Contains(autoTags(with), "set-cookie") {
		t.Fatalf("%v", autoTags(with))
	}
	lower := &Session{
		Request:  HTTPMsg{URL: "http://example.local/", Headers: map[string]string{}},
		Response: &HTTPMsg{StatusCode: 200, Headers: map[string]string{"set-cookie": "a=b"}},
	}
	if !slices.Contains(autoTags(lower), "set-cookie") {
		t.Fatalf("case-insensitive Set-Cookie: %v", autoTags(lower))
	}
	without := &Session{
		Request:  HTTPMsg{URL: "http://example.local/", Headers: map[string]string{}},
		Response: &HTTPMsg{StatusCode: 200, Headers: map[string]string{"Content-Type": "text/plain"}},
	}
	if slices.Contains(autoTags(without), "set-cookie") {
		t.Fatalf("unexpected set-cookie: %v", autoTags(without))
	}
}

func TestAutoTagsGraphQLPath(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		{"http://example.local/graphql", true},
		{"http://example.local/api/graphql", true},
		{"http://example.local/GraphQL", true},
		{"http://example.local/v1/graphql/", true},
		{"http://example.local/search?q=graphql", false},
		{"http://example.local/api/users", false},
	}
	for _, tc := range cases {
		t.Run(tc.url, func(t *testing.T) {
			sess := &Session{
				Request:  HTTPMsg{URL: tc.url, Headers: map[string]string{}},
				Response: &HTTPMsg{StatusCode: 200, Headers: map[string]string{}},
			}
			got := slices.Contains(autoTags(sess), "graphql")
			if got != tc.want {
				t.Fatalf("graphql=%v want %v tags=%v", got, tc.want, autoTags(sess))
			}
		})
	}
}

func TestAutoTagsGraphQLBody(t *testing.T) {
	cases := []struct {
		name string
		body string
		enc  string
		want bool
	}{
		{"json query", `{"query":"query { user { id } }"}`, "utf8", true},
		{"json mutation", `{"query":"mutation { x }","variables":{}}`, "utf8", true},
		{"raw query", "query { user { id } }", "utf8", true},
		{"raw mutation", "mutation Create { x }", "utf8", true},
		{"raw subscription", "subscription {\n  tick\n}", "utf8", true},
		{"not graphql json", `{"ok":true}`, "utf8", false},
		{"empty query field", `{"query":"  "}`, "utf8", false},
		{"unrelated text", "hello world", "utf8", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sess := &Session{
				Request: HTTPMsg{
					URL:     "http://example.local/api",
					Headers: map[string]string{},
					Body:    Body{Encoding: tc.enc, Content: tc.body},
				},
				Response: &HTTPMsg{StatusCode: 200, Headers: map[string]string{}},
			}
			got := slices.Contains(autoTags(sess), "graphql")
			if got != tc.want {
				t.Fatalf("graphql=%v want %v tags=%v", got, tc.want, autoTags(sess))
			}
		})
	}
	t.Run("base64 body", func(t *testing.T) {
		raw := `{"query":"{ ping }"}`
		sess := &Session{
			Request: HTTPMsg{
				URL:     "http://example.local/api",
				Headers: map[string]string{},
				Body:    Body{Encoding: "base64", Content: base64.StdEncoding.EncodeToString([]byte(raw))},
			},
			Response: &HTTPMsg{StatusCode: 200, Headers: map[string]string{}},
		}
		if !slices.Contains(autoTags(sess), "graphql") {
			t.Fatalf("%v", autoTags(sess))
		}
	})
}

func TestMergeTagsPreservesExisting(t *testing.T) {
	sess := &Session{
		Request:  HTTPMsg{URL: "http://example.local/", Headers: map[string]string{"Content-Type": "application/json"}},
		Response: &HTTPMsg{StatusCode: 200, Headers: map[string]string{"Content-Type": "application/json"}},
	}
	got := mergeTags([]string{"autoresponded", "replayed_from:abc"}, autoTags(sess))
	for _, want := range []string{"autoresponded", "replayed_from:abc", "json", "2xx"} {
		if !slices.Contains(got, want) {
			t.Fatalf("missing %s in %v", want, got)
		}
	}
	dup := mergeTags([]string{"json", "2xx"}, autoTags(sess))
	count := 0
	for _, name := range dup {
		if name == "json" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("duplicate json: %v", dup)
	}
}
