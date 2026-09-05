package crawler

import (
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/shroodler/crawler-go/internal/extractors"
	"github.com/shroodler/crawler-go/internal/models"
)

// sessionCookiesFromJar mirrors Python's session_checks.py::session_cookies:
// the session-shaped cookies (by name) the jar currently holds for seedURL's
// origin, as a name->value map.
func sessionCookiesFromJar(jar http.CookieJar, seedURL *url.URL) map[string]string {
	out := map[string]string{}
	if jar == nil || seedURL == nil {
		return out
	}
	for _, c := range jar.Cookies(seedURL) {
		if extractors.IsSessionCookie(c.Name) {
			out[c.Name] = c.Value
		}
	}
	return out
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
