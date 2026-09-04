package crawler

import (
	"net/http"
	"testing"
	"time"
)

// White-box tests for the unexported probeCORS/probe-skip helpers, covering
// the --allow-external plumbing that the black-box tests in crawler_test.go
// can't reach (Crawl itself refuses the whole crawl before reaching these
// when the top-level target is non-local and AllowExternal is false, so a
// non-local *candidate* under an allow-external crawl is the only way these
// paths are exercised in practice).

func TestProbeCORSHonorsAllowExternal(t *testing.T) {
	client := &http.Client{Timeout: 2 * time.Second}

	skipped := probeCORS(client, "https://example.com/", []string{"https://example.com/api/x"}, false)
	if len(skipped) != 1 || skipped[0].ID != "cors-probe-skipped" || skipped[0].Category != "scan-note" {
		t.Fatalf("expected a single scan-note skip finding, got %#v", skipped)
	}

	// allow_external=true with an unreachable candidate should attempt the
	// probe (and fail the request silently) rather than skip outright -- the
	// point is it does not return the skip finding.
	attempted := probeCORS(client, "https://example.invalid/", []string{"https://example.invalid/api/x"}, true)
	for _, f := range attempted {
		if f.ID == "cors-probe-skipped" {
			t.Fatalf("allow_external=true must not emit cors-probe-skipped, got %#v", attempted)
		}
	}
}

func TestGraphqlProbeSkippedFindingShape(t *testing.T) {
	f := graphqlProbeSkippedFinding("https://example.com/")
	if f.ID != "graphql-probe-skipped" || f.Category != "scan-note" || f.Severity != "info" {
		t.Fatalf("unexpected finding shape: %#v", f)
	}
}
