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
//
// Both header and "weak" body signatures are common on ordinary, non-blocked
// traffic (cf-ray is stamped on every Cloudflare-proxied response; reCAPTCHA/
// hCaptcha/Turnstile/DataDome are routinely embedded by site owners on normal
// login/signup forms as a deliberate anti-abuse control, not only on block
// pages) -- so neither counts as a hit unless paired with a 403/503 status.
// Only "strong" body phrases (the interstitial's own wording, e.g.
// Cloudflare's "Just a moment...") are specific enough to fire standalone.

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

// Fire on their own, any status: these are the interstitial page's own
// wording, not a widget/tag that a site might embed on an ordinary page.
var challengeStrongBodySignatures = []bodySignature{
	{regexp.MustCompile(`(?i)just a moment`), "Cloudflare"},
	{regexp.MustCompile(`(?i)checking your browser before accessing`), "Cloudflare"},
	{regexp.MustCompile(`(?i)id=["']challenge-form["']`), "Cloudflare"},
	{regexp.MustCompile(`(?i)access denied.{0,80}akamai`), "Akamai"},
	{regexp.MustCompile(`(?i)sucuri.{0,40}(firewall|website firewall)`), "Sucuri"},
}

// Only count as a hit paired with a 403/503 status: these are widgets/tags
// vendors' own SDKs tell site owners to embed directly on normal forms
// (login, signup, contact) as a proactive anti-abuse control, so seeing the
// tag alone is not evidence this particular response is a block page.
var challengeWeakBodySignatures = []bodySignature{
	{regexp.MustCompile(`(?i)cf-turnstile|cf_chl_opt`), "Cloudflare Turnstile"},
	{regexp.MustCompile(`(?i)hcaptcha`), "hCaptcha"},
	{regexp.MustCompile(`(?i)g-recaptcha|recaptcha/api`), "reCAPTCHA"},
	{regexp.MustCompile(`(?i)perimeterx|_pxCaptcha|px-captcha`), "PerimeterX"},
	{regexp.MustCompile(`(?i)datadome`), "DataDome"},
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

func matchChallengeBody(sigs []bodySignature, body string) string {
	for _, sig := range sigs {
		if sig.pattern.MatchString(body) {
			return sig.vendor
		}
	}
	return ""
}

func isBlockStatus(status int) bool {
	return status == 403 || status == 503
}

// DetectChallenge returns a finding if this response looks like a
// WAF/bot-mitigation challenge/interstitial page rather than real target
// content. Only a "strong" body signature fires on its own; a bare header
// signature or a "weak" body signature only counts as a hit paired with a
// 403/503 status.
func DetectChallenge(headers map[string]string, body string, status int) *models.Finding {
	if vendor := matchChallengeBody(challengeStrongBodySignatures, body); vendor != "" {
		return challengeFinding(vendor, status)
	}
	if isBlockStatus(status) {
		vendor := matchChallengeBody(challengeWeakBodySignatures, body)
		if vendor == "" {
			vendor = matchChallengeHeaders(headers)
		}
		if vendor != "" {
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
		"authorized scan, try --user-agent to rule out UA-based blocking, or ask " +
		"the target's operator to allowlist the scanner's source IP/User-Agent."
	return &models.Finding{
		ID:          "waf-challenge-detected",
		Severity:    "medium",
		Category:    "waf-challenge",
		Description: desc,
	}
}
