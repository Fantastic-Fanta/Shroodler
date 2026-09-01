package extractors

import (
	"encoding/xml"
	"io"
	"strings"
)

// ParseRobotsSitemaps returns Sitemap: directive URLs from a robots.txt body.
func ParseRobotsSitemaps(body string) []string {
	var out []string
	for _, raw := range strings.Split(body, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lower := strings.ToLower(line)
		if !strings.HasPrefix(lower, "sitemap:") {
			continue
		}
		rest := strings.TrimSpace(line[len("Sitemap:"):])
		if i := strings.Index(lower, "sitemap:"); i >= 0 {
			rest = strings.TrimSpace(line[i+len("sitemap:"):])
		}
		if rest == "" {
			continue
		}
		token := strings.Fields(rest)[0]
		if strings.HasPrefix(token, "#") {
			continue
		}
		out = append(out, token)
	}
	return out
}

// ParseSitemapXML returns url <loc> values and nested sitemap-index <loc> values.
// Malformed XML does not panic; it returns whatever was parsed before the error.
func ParseSitemapXML(body string) (urlLocs, sitemapLocs []string) {
	if strings.TrimSpace(body) == "" {
		return nil, nil
	}
	dec := xml.NewDecoder(strings.NewReader(body))
	dec.CharsetReader = func(_ string, input io.Reader) (io.Reader, error) {
		return input, nil
	}
	var stack []string
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			local := strings.ToLower(t.Name.Local)
			stack = append(stack, local)
			if local != "loc" {
				continue
			}
			var loc string
			if err := dec.DecodeElement(&loc, &t); err != nil {
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
				continue
			}
			loc = strings.TrimSpace(loc)
			parent := ""
			if len(stack) >= 2 {
				parent = stack[len(stack)-2]
			}
			if loc != "" {
				if parent == "sitemap" {
					sitemapLocs = append(sitemapLocs, loc)
				} else {
					urlLocs = append(urlLocs, loc)
				}
			}
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case xml.EndElement:
			if len(stack) == 0 {
				continue
			}
			stack = stack[:len(stack)-1]
		}
	}
	return urlLocs, sitemapLocs
}
