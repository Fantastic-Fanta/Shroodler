package crawler

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shroodler/crawler-go/internal/extractors"
	"github.com/shroodler/crawler-go/internal/models"
)

// cookieRecorder mirrors Python's session_checks.py::session_cookies /
// httpx's client.cookies: it accumulates every cookie ever seen on a
// Set-Cookie response for this crawl's client, with NO per-URL domain/path
// scoping. That matters: a Go http.CookieJar's Cookies(u) only returns
// cookies whose Path/Domain match u, so if a real app scopes its session
// cookie narrower than the crawl's seed URL (or the login endpoint is on a
// different path/host than the seed), jar-based lookup would silently see
// nothing -- while Python's flat dict sees it regardless of scope. This
// recorder matches Python's looser (and, since it's what both engines'
// tests are written against, the "correct" for parity) semantics directly,
// by snooping every response's Set-Cookie headers as they go by.
type cookieRecorder struct {
	mu      sync.Mutex
	cookies map[string]string
}

func newCookieRecorder() *cookieRecorder {
	return &cookieRecorder{cookies: map[string]string{}}
}

func (r *cookieRecorder) record(resp *http.Response) {
	if resp == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range resp.Cookies() {
		r.cookies[c.Name] = c.Value
	}
}

// sessionCookies returns a snapshot (a fresh copy) of the session-shaped
// cookies seen so far, by name.
func (r *cookieRecorder) sessionCookies() map[string]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]string{}
	for name, value := range r.cookies {
		if extractors.IsSessionCookie(name) {
			out[name] = value
		}
	}
	return out
}

// cookieRecordingTransport wraps a RoundTripper to feed every response
// through a cookieRecorder, independent of the client's Jar.
type cookieRecordingTransport struct {
	base http.RoundTripper
	rec  *cookieRecorder
}

func (t *cookieRecordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	resp, err := base.RoundTrip(req)
	if err == nil && t.rec != nil {
		t.rec.record(resp)
	}
	return resp, err
}

// checkSessionFixation mirrors session_checks.py::check_session_fixation.
func checkSessionFixation(pre, post map[string]string, pageURL string) []models.Finding {
	var out []models.Finding
	for name, preValue := range pre {
		if preValue == "" {
			continue
		}
		if postValue, ok := post[name]; ok && postValue == preValue {
			ev := name
			out = append(out, models.Finding{
				ID:       "session-fixation",
				Severity: "high",
				Category: "auth",
				URL:      pageURL,
				Description: "Session cookie '" + name + "' kept the same value before and " +
					"after login -- the application does not appear to regenerate the " +
					"session identifier on authentication. An attacker who sets or knows " +
					"the pre-auth session ID can hijack the session once the victim logs in.",
				Evidence: &ev,
			})
		}
	}
	return out
}

// checkLogoutInvalidation mirrors session_checks.py::check_logout_invalidation.
// It deliberately uses a fresh, jar-less client so it can replay the exact
// stale Cookie header manually, independent of whatever the crawl's shared
// jar has rotated to since login.
func checkLogoutInvalidation(logoutURL, logoutMethod, protectedURL, staleCookieHeader string, timeout time.Duration) []models.Finding {
	if staleCookieHeader == "" {
		return nil
	}
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	method := strings.ToUpper(logoutMethod)
	if method == "" {
		method = http.MethodGet
	}
	logoutReq, err := http.NewRequest(method, logoutURL, nil)
	if err != nil {
		return nil
	}
	logoutReq.Header.Set("Cookie", staleCookieHeader)
	if resp, err := client.Do(logoutReq); err == nil {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 2_000_000))
		resp.Body.Close()
	} else {
		return nil
	}

	checkReq, err := http.NewRequest(http.MethodGet, protectedURL, nil)
	if err != nil {
		return nil
	}
	checkReq.Header.Set("Cookie", staleCookieHeader)
	resp, err := client.Do(checkReq)
	if err != nil {
		return nil
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 2_000_000))
	resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		ev := "status=" + strconv.Itoa(resp.StatusCode)
		return []models.Finding{{
			ID:       "logout-session-not-invalidated",
			Severity: "high",
			Category: "auth",
			URL:      protectedURL,
			Description: "Replaying the pre-logout session cookie against " + protectedURL +
				" after logging out still succeeded (status " + strconv.Itoa(resp.StatusCode) + ") -- " +
				"the server-side session was not invalidated on logout, so a stolen session " +
				"cookie stays usable even after the legitimate user logs out.",
			Evidence: &ev,
		}}
	}
	return nil
}

func cookieHeaderFromMap(cookies map[string]string) string {
	parts := make([]string, 0, len(cookies))
	for name, value := range cookies {
		parts = append(parts, name+"="+value)
	}
	return strings.Join(parts, "; ")
}
