package report

import (
	"encoding/json"
	"strings"
	"testing"
)

func sampleDoc() map[string]any {
	return map[string]any{
		"target": "http://127.0.0.1:8081",
		"crawler": map[string]any{
			"name": "shroodler-go", "version": "0.1.0", "mode": "static",
		},
		"pages": []any{map[string]any{"url": "http://127.0.0.1:8081/"}},
		"findings": []any{
			map[string]any{
				"id": "a", "severity": "info", "category": "header",
				"url": "http://127.0.0.1:8081/", "description": "info finding",
			},
			map[string]any{
				"id": "b", "severity": "critical", "category": "secret",
				"url": "http://127.0.0.1:8081/", "description": "crit finding",
				"evidence": "AKIAIOSFODNN7EXAMPLE",
			},
			map[string]any{
				"id": "e", "severity": "medium", "category": "header",
				"url": "http://127.0.0.1:8081/login", "description": "med finding",
			},
		},
	}
}

func TestRenderSARIF(t *testing.T) {
	raw := RenderSARIF(sampleDoc())
	var sarif map[string]any
	if err := json.Unmarshal([]byte(raw), &sarif); err != nil {
		t.Fatal(err)
	}
	if sarif["version"] != "2.1.0" {
		t.Fatalf("version %v", sarif["version"])
	}
	runs := sarif["runs"].([]any)
	run := runs[0].(map[string]any)
	results := run["results"].([]any)
	if len(results) != 3 {
		t.Fatalf("results %d", len(results))
	}
	levels := map[string]string{}
	for _, r := range results {
		m := r.(map[string]any)
		levels[m["ruleId"].(string)] = m["level"].(string)
		locs := m["locations"].([]any)
		phys := locs[0].(map[string]any)["physicalLocation"].(map[string]any)
		uri := phys["artifactLocation"].(map[string]any)["uri"]
		if uri == "" {
			t.Fatal("missing uri")
		}
	}
	if levels["b"] != "error" || levels["e"] != "warning" || levels["a"] != "note" {
		t.Fatalf("levels %#v", levels)
	}
	empty := RenderSARIF(map[string]any{"findings": []any{}})
	var emptyDoc map[string]any
	if err := json.Unmarshal([]byte(empty), &emptyDoc); err != nil {
		t.Fatal(err)
	}
	emptyResults := emptyDoc["runs"].([]any)[0].(map[string]any)["results"]
	if emptyResults == nil {
		t.Fatal("empty results must be an array, not null")
	}
}

func TestRenderMarkdown(t *testing.T) {
	md := RenderMarkdown(sampleDoc())
	if !strings.HasPrefix(md, "# Shroodler report") {
		t.Fatalf("header: %s", md[:40])
	}
	crit := strings.Index(md, "## critical")
	med := strings.Index(md, "## medium")
	info := strings.Index(md, "## info")
	if crit < 0 || med < 0 || info < 0 || !(crit < med && med < info) {
		t.Fatalf("severity order crit=%d med=%d info=%d\n%s", crit, med, info, md)
	}
	if !strings.Contains(md, "`b`") || !strings.Contains(md, "http://127.0.0.1:8081/") {
		t.Fatal("missing id/url")
	}
	if !strings.Contains(md, "crit finding") {
		t.Fatal("missing description")
	}
	if strings.Contains(md, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatal("full secret leaked in markdown")
	}
	if !strings.Contains(md, "AKIA************MPLE") {
		t.Fatalf("expected redacted evidence, got %s", md)
	}
	empty := RenderMarkdown(map[string]any{
		"target": "http://127.0.0.1:8081", "findings": []any{}, "pages": []any{},
	})
	if !strings.Contains(empty, "No findings.") {
		t.Fatalf("empty: %s", empty)
	}
}

func TestFormatEvidence(t *testing.T) {
	if got := FormatEvidence("AKIA****"); got != "AKIA****" {
		t.Fatalf("short already-redacted: %s", got)
	}
	if got := FormatEvidence("/.git/HEAD"); got != "/.git/HEAD" {
		t.Fatalf("path: %s", got)
	}
	long := strings.Repeat("word ", 30)
	if got := FormatEvidence(long); !strings.HasSuffix(got, "…") || len(got) > 80 {
		t.Fatalf("truncate: %q", got)
	}
}
