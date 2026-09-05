package crawler

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/shroodler/crawler-go/internal/models"
	"github.com/shroodler/crawler-go/internal/urls"
)

// AuthzDiffOptions mirrors authz_diff.py::run's keyword options. NoAnonCheck
// is inverted relative to Python's check_anonymous (which defaults true) so
// that Go's zero-value struct -- the natural way to call this API -- gets
// the anonymous control request by default, matching Python's behavior,
// instead of silently skipping it.
type AuthzDiffOptions struct {
	CookieHeader  string
	ExtraHeaders  map[string]string
	NoAnonCheck   bool
	AllowExternal bool
}

// AuthzDiffResult mirrors the {"target": ..., "findings": [...]} shape
// authz_diff.py::run returns.
type AuthzDiffResult struct {
	Target   string           `json:"target"`
	Findings []models.Finding `json:"findings"`
}

var loginRedirectHints = []string{"login", "signin", "sign-in", "log-in", "auth", "session/new"}

func isAuthzSuccess(status int) bool {
	return status >= 200 && status < 300
}

// isDenied: a response counts as "denied" only when it's an explicit
// 401/403, or a redirect that specifically looks like a bounce to a
// login/auth page. A bare 3xx is NOT enough on its own -- ordinary
// trailing-slash, HTTPS-upgrade, or locale redirects are common on pages
// that have nothing to do with authorization, and treating every redirect
// as a denial turns the anonymous control probe into a false-positive
// generator. (This exact bug was previously fixed once in the Python
// engine -- see CHANGELOG.md -- do not reintroduce it here.)
func isDenied(status int, location string) bool {
	if status == 401 || status == 403 {
		return true
	}
	switch status {
	case 301, 302, 303, 307, 308:
		loc := strings.ToLower(location)
		for _, hint := range loginRedirectHints {
			if strings.Contains(loc, hint) {
				return true
			}
		}
	}
	return false
}

// RunAuthzDiff replays a privileged crawl's page URLs under a second,
// lower-privileged session (mirrors authz_diff.py::run). It is a replay
// tool, not a crawler: it never discovers new URLs, only re-requests URLs
// the privileged crawl already found.
func RunAuthzDiff(higherDoc *models.CrawlResult, opts AuthzDiffOptions) (*AuthzDiffResult, error) {
	target := higherDoc.Target
	if !opts.AllowExternal && !urls.IsLocal(target) {
		return nil, errString(
			"authz-diff refuses non-local targets without --allow-external " +
				"(only scan hosts you are authorized to test)",
		)
	}
	client := &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	lowerHeaders := map[string]string{}
	for k, v := range opts.ExtraHeaders {
		lowerHeaders[k] = v
	}
	if opts.CookieHeader != "" {
		lowerHeaders["Cookie"] = opts.CookieHeader
	}

	findings := []models.Finding{}
	seen := map[string]bool{}
	for _, page := range higherDoc.Pages {
		url := page.URL
		if url == "" || seen[url] {
			continue
		}
		if !opts.AllowExternal && !urls.IsLocal(url) {
			continue
		}
		seen[url] = true

		lowerResp, err := authzGet(client, url, lowerHeaders)
		if err != nil {
			continue
		}
		if !isAuthzSuccess(lowerResp.status) {
			continue
		}

		if !opts.NoAnonCheck {
			anonHeaders := map[string]string{}
			for k, v := range lowerHeaders {
				if k != "Cookie" {
					anonHeaders[k] = v
				}
			}
			anonResp, anonErr := authzGet(client, url, anonHeaders)
			if anonErr == nil && isDenied(anonResp.status, anonResp.location) {
				ev := "lower=" + itoaStatus(lowerResp.status) + " anon=" + itoaStatus(anonResp.status)
				findings = append(findings, models.Finding{
					ID:       "authz-broken-access-control",
					Severity: "high",
					Category: "auth",
					URL:      url,
					Description: "URL discovered under the privileged session is also " +
						"reachable (status " + itoaStatus(lowerResp.status) + ") with the " +
						"lower-privilege session, while an anonymous request to the same " +
						"URL was denied (status " + itoaStatus(anonResp.status) + ") -- this " +
						"endpoint enforces *some* session but not the *right* one. Verify " +
						"whether the lower-privilege session should be able to see this resource.",
					Evidence: &ev,
				})
				continue
			}
			if anonErr == nil && isAuthzSuccess(anonResp.status) {
				// Anonymous access already succeeds -- this resource is
				// confirmed public, so the lower-priv session reaching it
				// too isn't a finding.
				continue
			}
		}

		ev := "lower=" + itoaStatus(lowerResp.status)
		findings = append(findings, models.Finding{
			ID:       "authz-still-accessible",
			Severity: "medium",
			Category: "auth",
			URL:      url,
			Description: "URL discovered under the privileged session was also reachable " +
				"(status " + itoaStatus(lowerResp.status) + ") with the lower-privilege " +
				"session. Manually verify this is intentionally shared/public access, not " +
				"an access-control gap.",
			Evidence: &ev,
		})
	}

	return &AuthzDiffResult{Target: target, Findings: findings}, nil
}

type authzResponse struct {
	status   int
	location string
}

func authzGet(client *http.Client, url string, headers map[string]string) (authzResponse, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return authzResponse{}, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return authzResponse{}, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 2_000_000))
	return authzResponse{status: resp.StatusCode, location: resp.Header.Get("Location")}, nil
}

func itoaStatus(n int) string {
	return strconv.Itoa(n)
}
