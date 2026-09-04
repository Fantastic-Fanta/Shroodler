package payload

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadPacksFromYAML(t *testing.T) {
	packs, err := LoadPacks()
	if err != nil {
		t.Fatal(err)
	}
	if len(packs) == 0 {
		t.Fatal("no packs")
	}
	ids := map[string]bool{}
	for _, p := range packs {
		ids[p.findingID()] = true
		if p.Payload == "" {
			t.Fatalf("empty payload %#v", p)
		}
	}
	for _, id := range []string{
		"payload-sql-error", "payload-xss-reflect", "payload-ssti", "payload-path-traversal",
	} {
		if !ids[id] {
			t.Fatalf("missing pack %s", id)
		}
	}
}

func TestLoadExtraPack(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "extra.yaml")
	if err := os.WriteFile(path, []byte("- id: extra-token\n  finding_id: payload-extra-reflect\n  payload: EXTRA_PACK_TOKEN\n  severity: low\n  match:\n    any:\n      - reflected: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	packs, err := LoadPacks(path)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, p := range packs {
		ids[p.findingID()] = true
	}
	if !ids["payload-extra-reflect"] || !ids["payload-sql-error"] {
		t.Fatalf("extra pack not merged: %#v", ids)
	}
}

func TestPackMatches(t *testing.T) {
	n := 500
	p := Pack{ID: "x", Payload: "abc", Match: Match{Any: []Clause{{StatusGte: &n}}}}
	if !PackMatches(p, 500, "ok", "abc") {
		t.Fatal("status")
	}
	p = Pack{ID: "y", Payload: "<x>", Match: Match{All: []Clause{{Reflected: true}}}}
	if PackMatches(p, 200, "nope", "<x>") {
		t.Fatal("should miss")
	}
	if !PackMatches(p, 200, "hi <x>", "<x>") {
		t.Fatal("reflected")
	}
}

func TestRunYAMLPacksAgainstLocalForm(t *testing.T) {
	packs, err := LoadPacks()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/search" || r.Method != http.MethodPost {
			w.Write([]byte("home"))
			return
		}
		_ = r.ParseForm()
		q := r.FormValue("q")
		switch {
		case strings.Contains(q, "../"):
			w.Write([]byte("root:x:0:0:root:/root:/bin/sh\n"))
		case strings.Contains(q, "{{7*7}}"):
			w.Write([]byte("computed:49"))
		case strings.Contains(q, "'") || strings.Contains(strings.ToLower(q), "or"):
			w.WriteHeader(500)
			w.Write([]byte(`sqlite3.OperationalError: syntax error`))
		default:
			w.Write([]byte("<p>no rows for " + q + "</p>"))
		}
	}))
	defer srv.Close()
	doc := map[string]any{
		"target": srv.URL + "/",
		"pages": []any{
			map[string]any{
				"url": srv.URL + "/",
				"forms": []any{
					map[string]any{
						"action": "/search",
						"method": "POST",
						"fields": []any{map[string]any{"name": "q"}},
					},
				},
			},
		},
	}
	out, err := Run(doc, srv.Client(), packs, false)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, f := range out.Findings {
		got[f.ID] = true
	}
	for _, id := range []string{
		"payload-sql-error", "payload-xss-reflect", "payload-ssti", "payload-path-traversal",
	} {
		if !got[id] {
			t.Fatalf("missing %s in %#v", id, out.Findings)
		}
	}
}

func TestRunRefusesExternal(t *testing.T) {
	_, err := Run(map[string]any{"target": "https://example.com/", "pages": []any{}}, nil, []Pack{}, false)
	if err == nil {
		t.Fatal("expected refuse")
	}
}

func TestRunAllowExternalBypassesGuard(t *testing.T) {
	out, err := Run(map[string]any{"target": "https://example.com/", "pages": []any{}}, nil, []Pack{}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 0 {
		t.Fatalf("expected no findings for empty pages, got %#v", out.Findings)
	}
}

func TestNewClauseTypes(t *testing.T) {
	statusChanged := Clause{ErrorStatusChanged: true}
	if !clauseMatches(statusChanged, 500, "", "x", matchCtx{haveBaseline: true, baselineStatus: 200}) {
		t.Fatal("expected error_status_changed to match")
	}
	if clauseMatches(statusChanged, 200, "", "x", matchCtx{haveBaseline: true, baselineStatus: 200}) {
		t.Fatal("error_status_changed should not match on unchanged status")
	}

	newOnly := Clause{BodyContains: "boom", NewOnly: true}
	if !clauseMatches(newOnly, 200, "boom here", "x", matchCtx{baselineBody: ""}) {
		t.Fatal("expected new_only body_contains to match when absent from baseline")
	}
	if clauseMatches(newOnly, 200, "boom here", "x", matchCtx{baselineBody: "already had boom"}) {
		t.Fatal("new_only body_contains should not match when present in baseline")
	}

	delta := 1000
	timeClause := Clause{TimeDeltaGteMs: &delta}
	if !clauseMatches(timeClause, 200, "", "x", matchCtx{haveElapsed: true, elapsedMs: 1600, haveBaselineTime: true, baselineElapsed: 200}) {
		t.Fatal("expected time_delta_gte_ms to match")
	}

	redirect := Clause{RedirectedToContain: "evil.test"}
	if !clauseMatches(redirect, 200, "", "x", matchCtx{redirectedTo: "https://evil.test/x"}) {
		t.Fatal("expected redirected_to_contains to match")
	}
}

func TestRenderPayloadTokenAndMarker(t *testing.T) {
	token := genToken()
	if !strings.HasPrefix(token, "shrdlr") {
		t.Fatalf("unexpected token shape: %s", token)
	}
	rendered := renderPayload("<script>{{TOKEN}}</script>//{{MARKER_HOST}}/", token)
	if !strings.Contains(rendered, token) || !strings.Contains(rendered, MarkerHost) {
		t.Fatalf("render did not substitute placeholders: %s", rendered)
	}
}

func TestNewPacksLoadWithoutError(t *testing.T) {
	packs, err := LoadPacks()
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, p := range packs {
		ids[p.findingID()] = true
	}
	for _, id := range []string{"payload-ssrf", "payload-open-redirect", "payload-sql-time-blind"} {
		if !ids[id] {
			t.Fatalf("missing pack %s", id)
		}
	}
}
