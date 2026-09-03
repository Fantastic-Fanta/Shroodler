package extractors

import (
	"net/url"
	"strings"

	"github.com/shroodler/crawler-go/internal/models"
)

const (
	AttackerOrigin = "https://evil.example"
	MaxCORSProbes  = 32
)

var staticSuffixes = []string{
	".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
	".woff", ".woff2", ".ttf", ".eot", ".webp", ".avif",
}

func corsHeader(h map[string]string, name string) string {
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func pathOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Path == "" {
		if strings.HasPrefix(raw, "/") {
			return strings.ToLower(raw)
		}
		return "/"
	}
	return strings.ToLower(u.Path)
}

func IsStaticAsset(raw string) bool {
	path := pathOf(raw)
	for _, ext := range staticSuffixes {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

func IsAPIPath(raw string) bool {
	path := pathOf(raw)
	return path == "/api" || strings.HasPrefix(path, "/api/") || strings.Contains(path, "/api/")
}

func IsJSONContentType(ct string) bool {
	low := strings.ToLower(ct)
	return strings.Contains(low, "application/json") || strings.Contains(low, "application/problem+json")
}

func IsAPIIsh(raw, contentType string) bool {
	if IsStaticAsset(raw) {
		return false
	}
	return IsAPIPath(raw) || IsJSONContentType(contentType)
}

func CORSFindings(headers map[string]string, pageURL string) []models.Finding {
	acao := corsHeader(headers, "access-control-allow-origin")
	acac := corsHeader(headers, "access-control-allow-credentials")
	if acao == "" {
		return nil
	}
	creds := strings.EqualFold(acac, "true")
	evidence := "ACAO=" + acao
	if acac != "" {
		evidence += " ACAC=" + acac
	}
	var out []models.Finding
	if acao == "*" && creds {
		ev := evidence
		out = append(out, models.Finding{
			ID: "cors-wildcard-credentials", Severity: "high", Category: "header",
			URL: pageURL, Description: "Access-Control-Allow-Origin is * with Access-Control-Allow-Credentials true",
			Evidence: &ev,
		})
	} else if acao == "*" {
		ev := evidence
		out = append(out, models.Finding{
			ID: "cors-allow-any", Severity: "info", Category: "header",
			URL: pageURL, Description: "Access-Control-Allow-Origin is * (credentials not enabled)",
			Evidence: &ev,
		})
	}
	if acao == AttackerOrigin {
		sev := "medium"
		if creds {
			sev = "high"
		}
		ev := evidence
		out = append(out, models.Finding{
			ID: "cors-reflect-origin", Severity: sev, Category: "header",
			URL: pageURL, Description: "Access-Control-Allow-Origin reflects the attacker Origin",
			Evidence: &ev,
		})
	}
	return out
}
