package extractors

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"

	"github.com/shroodler/crawler-go/internal/models"
)

var sourceMapRe = regexp.MustCompile(`(?://[#@]|/\*)\s*sourceMappingURL=(\S+)`)

func SourceMappingURL(js string) string {
	ms := sourceMapRe.FindAllStringSubmatch(js, -1)
	if len(ms) == 0 {
		return ""
	}
	spec := strings.TrimRight(ms[len(ms)-1][1], "*/")
	return strings.TrimSpace(spec)
}

func DecodeDataURL(spec string) []byte {
	if !strings.HasPrefix(spec, "data:") {
		return nil
	}
	comma := strings.Index(spec, ",")
	if comma < 0 {
		return nil
	}
	header := strings.ToLower(spec[5:comma])
	rest := spec[comma+1:]
	if strings.Contains(header, ";base64") {
		b, err := base64.StdEncoding.DecodeString(rest)
		if err != nil {
			return nil
		}
		return b
	}
	u, err := url.QueryUnescape(rest)
	if err != nil {
		return []byte(rest)
	}
	return []byte(u)
}

type sourceMapFile struct {
	Sources        []string  `json:"sources"`
	SourcesContent []*string `json:"sourcesContent"`
}

func ParseSourceMap(jsURL string, raw []byte, rules []Rule) ([]models.JSEndpoint, []models.Finding) {
	var obj sourceMapFile
	if json.Unmarshal(raw, &obj) != nil {
		return nil, nil
	}
	var eps []models.JSEndpoint
	var findings []models.Finding
	for i, src := range obj.Sources {
		if i >= len(obj.SourcesContent) || obj.SourcesContent[i] == nil || *obj.SourcesContent[i] == "" {
			continue
		}
		original := src
		if original == "" {
			original = "source[" + itoa(i) + "]"
		}
		text := *obj.SourcesContent[i]
		got := ExtractJSEndpoints(jsURL, text)
		eps = append(eps, got...)
		var extra []models.Finding
		for _, e := range got {
			ev := e.Endpoint + " @ " + original
			extra = append(extra, models.Finding{
				ID: "js-endpoint", Severity: "info", Category: "js-endpoint",
				URL: jsURL, Description: "JS references endpoint " + e.Endpoint + " (original " + original + ")", Evidence: &ev,
			})
		}
		secrets := ScanSecrets(text, jsURL, rules)
		for i := range secrets {
			secrets[i].Description += " (original " + original + ")"
			if secrets[i].Evidence != nil {
				ev := *secrets[i].Evidence + " @ " + original
				secrets[i].Evidence = &ev
			} else {
				secrets[i].Evidence = &original
			}
		}
		findings = append(findings, extra...)
		findings = append(findings, secrets...)
	}
	return eps, findings
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for n > 0 {
		d = append([]byte{byte('0' + n%10)}, d...)
		n /= 10
	}
	return string(d)
}
