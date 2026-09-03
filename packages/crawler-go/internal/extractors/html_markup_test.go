package extractors

import (
	"strings"
	"testing"
)

func TestLoadCommentKeywords(t *testing.T) {
	keys := map[string]bool{}
	for _, k := range LoadCommentKeywords() {
		keys[strings.ToUpper(k)] = true
	}
	for _, need := range []string{"TODO", "FIXME", "PASSWORD", "API_KEY"} {
		if !keys[need] {
			t.Fatalf("missing keyword %s in %v", need, keys)
		}
	}
}

func TestHTMLCommentKeywordAndBoring(t *testing.T) {
	fs := ExtractHTMLComments(
		`<html><body><!-- TODO: remove debug admin at /nope --><!-- layout --></body></html>`,
		"http://127.0.0.1/",
		nil,
	)
	if len(fs) != 1 || fs[0].ID != "html-comment" || fs[0].Category != "verbose-error" || fs[0].Severity != "info" {
		t.Fatalf("%#v", fs)
	}
	if fs[0].Evidence == nil || !strings.Contains(*fs[0].Evidence, "TODO") {
		t.Fatalf("evidence %v", fs[0].Evidence)
	}
	if got := ExtractHTMLComments(`<html><body><!-- layout --></body></html>`, "http://127.0.0.1/about", nil); len(got) != 0 {
		t.Fatalf("boring comment reported: %#v", got)
	}
}

func TestHTMLCommentSecretCategory(t *testing.T) {
	rules := []Rule{{ID: "aws-access-key", Pattern: `AKIA[0-9A-Z]{16}`, Severity: "high", Description: "aws"}}
	fs := ExtractHTMLComments(
		`<html><body><!-- TODO: AKIAIOSFODNN7EXAMPLE --></body></html>`,
		"http://127.0.0.1/",
		rules,
	)
	if len(fs) != 1 || fs[0].ID != "html-comment" || fs[0].Category != "secret" {
		t.Fatalf("%#v", fs)
	}
}

func TestMetaGeneratorPresentAndAbsent(t *testing.T) {
	fs := ExtractMetaGenerator(
		`<html><head><meta name="generator" content="App1CMS 0.1.0"></head></html>`,
		"http://127.0.0.1/",
	)
	if len(fs) != 1 || fs[0].ID != "meta-generator" || fs[0].Category != "header" || fs[0].Severity != "info" {
		t.Fatalf("%#v", fs)
	}
	if fs[0].Evidence == nil || *fs[0].Evidence != "App1CMS 0.1.0" {
		t.Fatalf("evidence %v", fs[0].Evidence)
	}
	if got := ExtractMetaGenerator(`<html><head><meta name="viewport" content="width=device-width"></head></html>`, "http://127.0.0.1/"); len(got) != 0 {
		t.Fatalf("missing generator should be empty: %#v", got)
	}
}

func TestExtractHTMLMarkupCombines(t *testing.T) {
	fs := ExtractHTMLMarkup(
		`<html><head><meta name="Generator" content="App1CMS 0.1.0"></head>
		<body><!-- FIXME leftover --><!-- layout --></body></html>`,
		"http://127.0.0.1/",
		nil,
	)
	ids := map[string]bool{}
	for _, f := range fs {
		ids[f.ID] = true
	}
	if !ids["html-comment"] || !ids["meta-generator"] {
		t.Fatalf("%#v", fs)
	}
}
