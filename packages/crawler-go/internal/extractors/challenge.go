package extractors

import (
	"regexp"
	"strings"

	"github.com/shroodler/crawler-go/internal/models"
)

// Detection only -- this never attempts to solve, bypass, or evade a
// challenge. Its only job is to stop the crawler from silently treating a
// WAF/bot-mitigation interstitial as real page content (a false negative: a
// "clean" scan against a challenge-fronted target currently means nothing).

type headerSignature struct {
	name, needle, vendor string
}

var challengeHeaderSignatures = []headerSignature{
	{"server", "cloudflare", "Cloudflare"},
	{"cf-mitigated", "", "Cloudflare"},
	{"cf-ray", "", "Cloudflare"},
	{"x-datadome", "", "DataDome"},
	{"x-akamai-transformed", "", "Akamai"},
	{"server", "akamaighost", "Akamai"},
	{"x-px-block", "", "PerimeterX"},
	{"perimeterx", "", "PerimeterX"},
	{"x-sucuri-id", "", "Sucuri"},
}

type bodySignature struct {
	pattern *regexp.Regexp
	vendor  string
}

var challengeBodySignatures = []bodySignature{
	{regexp.MustCompile(`(?i)just a moment`), "Cloudflare"},
	{regexp.MustCompile(`(?i)checking your browser before accessing`), "Cloudflare"},
	{regexp.MustCompile(`(?i)id=["']challenge-form["']`), "Cloudflare"},
	{regexp.MustCompile(`(?i)cf-turnstile|cf_chl_opt`), "Cloudflare Turnstile"},
	{regexp.MustCompile(`(?i)hcaptcha`), "hCaptcha"},
	{regexp.MustCompile(`(?i)g-recaptcha|recaptcha/api`), "reCAPTCHA"},
	{regexp.MustCompile(`(?i)perimeterx|_pxCaptcha|px-captcha`), "PerimeterX"},
	{regexp.MustCompile(`(?i)datadome`), "DataDome"},
	{regexp.MustCompile(`(?i)access denied.{0,80}akamai`), "Akamai"},
	{regexp.MustCompile(`(?i)sucuri.{0,40}(firewall|website firewall)`), "Sucuri"},
}

func challengeHeader(h map[string]string, name string) string {
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

func matchChallengeHeaders(headers map[string]string) string {
	for _, sig := range challengeHeaderSignatures {
		value := challengeHeader(headers, sig.name)
		if value == "" {
			continue
		}
		if sig.needle == "" || strings.Contains(strings.ToLower(value), sig.needle) {
			return sig.vendor
		}
	}
	return ""
}

func matchChallengeBody(body string) string {
	for _, sig := range challengeBodySignatures {
		if sig.pattern.MatchString(body) {
			return sig.vendor
		}
	}
	return ""
}

// DetectChallenge returns a finding if this response looks like a
// WAF/bot-mitigation challenge/interstitial page rather than real target
// content. Header signatures alone (e.g. a plain cf-ray header on an
// otherwise normal 200 response, which Cloudflare adds to all proxied
// traffic) are not sufficient on their own -- only header signatures paired
// with a small/error-shaped response, or a body-content signature, count.
func DetectChallenge(headers map[string]string, body string, status int) *models.Finding {
	if vendor := matchChallengeBody(body); vendor != "" {
		return challengeFinding(vendor, status)
	}
	if vendor := matchChallengeHeaders(headers); vendor != "" {
		if status == 403 || status == 503 || len(body) < 4000 {
			return challengeFinding(vendor, status)
		}
	}
	return nil
}

func challengeFinding(vendor string, status int) *models.Finding {
	desc := "Response looks like a " + vendor + " challenge/interstitial page, not " +
		"real target content -- the crawler stopped extracting forms/secrets/" +
		"links from this page. Passive/active checks against this URL were not " +
		"meaningfully performed. This is a detection-only signal: Shroodler does " +
		"not attempt to solve or bypass challenges. If this is unexpected on an " +
		"authorized scan, ask the target's operator to allowlist the scanner's " +
		"source IP/User-Agent."
	return &models.Finding{
		ID:          "waf-challenge-detected",
		Severity:    "high",
		Category:    "waf-challenge",
		Description: desc,
	}
}
