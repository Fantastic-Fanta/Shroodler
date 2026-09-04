package crawler

import (
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/shroodler/crawler-go/internal/models"
)

var loginActionHints = []string{
	"login", "signin", "sign-in", "log-in", "auth", "authenticate",
	"reset-password", "forgot-password", "password-reset",
}

var lockoutKeywords = []string{
	"too many attempts", "too many requests", "rate limit", "rate-limit",
	"try again later", "temporarily locked", "temporarily blocked",
	"account locked", "captcha",
}

const rateLimitAttempts = 6

// isLoginShaped is a heuristic for whether a form looks like a login/auth
// endpoint -- used to scope --check-rate-limit probing to forms where
// hammering the endpoint with repeated requests is actually meaningful.
func isLoginShaped(f models.Form) bool {
	for _, field := range f.Fields {
		if strings.ToLower(field.Type) == "password" {
			return true
		}
	}
	action := strings.ToLower(f.Action)
	for _, hint := range loginActionHints {
		if strings.Contains(action, hint) {
			return true
		}
	}
	return false
}

func rateLimitProbeValues(f models.Form, attempt int) url.Values {
	vals := url.Values{}
	for _, field := range f.Fields {
		if field.Name == "" {
			continue
		}
		if strings.ToLower(field.Type) == "password" {
			vals.Set(field.Name, "shroodler-rl-probe-wrong-"+strconv.Itoa(attempt))
		} else {
			vals.Set(field.Name, "shroodler-rl-probe")
		}
	}
	return vals
}

func doPostForm(client *http.Client, raw string, vals url.Values) fetchResult {
	req, err := http.NewRequest(http.MethodPost, raw, strings.NewReader(vals.Encode()))
	if err != nil {
		return fetchResult{URL: raw}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return doRequestObj(client, req, raw)
}

func doRequestObj(client *http.Client, req *http.Request, raw string) fetchResult {
	req.Header.Set("User-Agent", "Shroodler/0.1.0 (+https://shroodler.local)")
	resp, err := client.Do(req)
	if err != nil {
		return fetchResult{URL: raw}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 2_000_000))
	hdrs := map[string]string{}
	for k, vs := range resp.Header {
		if len(vs) > 0 {
			hdrs[k] = vs[0]
		}
	}
	return fetchResult{URL: raw, Status: resp.StatusCode, Headers: hdrs, Body: string(b), SetCookies: resp.Header.Values("Set-Cookie")}
}

// checkFormRateLimit fires rateLimitAttempts rapid bad-credential requests
// at a login-shaped form and flags it if nothing in the response stream
// (status, body) suggests any throttling, lockout, or CAPTCHA kicked in.
//
// This is opt-in (--check-rate-limit) and off by default: it deliberately
// sends multiple bad-credential attempts at a real endpoint, which has real
// consequences (account lockout, alerting, log noise) against a production
// target. Only call this against systems you're authorized to load-test.
func checkFormRateLimit(client *http.Client, action string, form models.Form) []models.Finding {
	method := strings.ToUpper(form.Method)
	if method == "" {
		method = "POST"
	}
	statuses := make([]int, 0, rateLimitAttempts)
	bodies := make([]string, 0, rateLimitAttempts)
	for i := 0; i < rateLimitAttempts; i++ {
		var res fetchResult
		if method == "GET" {
			res = doGet(client, action, "")
		} else {
			res = doPostForm(client, action, rateLimitProbeValues(form, i))
		}
		if res.Status == 0 {
			return nil
		}
		statuses = append(statuses, res.Status)
		bodies = append(bodies, strings.ToLower(res.Body))
	}
	for _, s := range statuses {
		if s == 429 {
			return nil
		}
	}
	for _, b := range bodies {
		for _, kw := range lockoutKeywords {
			if strings.Contains(b, kw) {
				return nil
			}
		}
	}
	first := statuses[0]
	for _, s := range statuses[1:] {
		if s != first {
			return nil
		}
	}
	ev := "6 requests, all status " + strconv.Itoa(first) + ", no lockout/CAPTCHA signal"
	desc := "Sent 6 rapid requests to this login/auth-shaped form with bad " +
		"credentials and saw no rate-limiting, lockout, or CAPTCHA response -- " +
		"the endpoint may be brute-forceable."
	return []models.Finding{{
		ID: "missing-rate-limit", Severity: "medium", Category: "auth",
		URL: action, Description: desc, Evidence: &ev,
	}}
}

// checkRateLimits scans every discovered page for login-shaped forms and
// probes each distinct action URL once.
func checkRateLimits(client *http.Client, origin string, pages []models.Page) []models.Finding {
	var out []models.Finding
	seen := map[string]bool{}
	for _, page := range pages {
		for _, form := range page.Forms {
			if !isLoginShaped(form) {
				continue
			}
			action := form.Action
			if action == "" {
				action = page.URL
			}
			if strings.HasPrefix(action, "/") {
				if u, err := url.Parse(page.URL); err == nil {
					action = u.Scheme + "://" + u.Host + action
				}
			}
			if seen[action] {
				continue
			}
			seen[action] = true
			out = append(out, checkFormRateLimit(client, action, form)...)
		}
	}
	return out
}
