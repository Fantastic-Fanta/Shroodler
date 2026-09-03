package report

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
)

var sarifLevel = map[string]string{
	"critical": "error",
	"high":     "error",
	"medium":   "warning",
	"low":      "note",
	"info":     "note",
}

var severityOrder = []string{"critical", "high", "medium", "low", "info"}

func asMaps(v any) []map[string]any {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(arr))
	for _, item := range arr {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func str(v any) string {
	if v == nil {
		return ""
	}
	s := fmt.Sprint(v)
	if s == "<nil>" {
		return ""
	}
	return s
}

// FormatEvidence redacts compact secret-like tokens and truncates long snippets.
func FormatEvidence(v any) string {
	text := str(v)
	if text == "" {
		return ""
	}
	compact := strings.TrimSpace(text)
	secretLike := true
	for _, r := range compact {
		if unicode.IsSpace(r) || r == '/' {
			secretLike = false
			break
		}
	}
	if len(compact) > 8 && secretLike {
		return compact[:4] + "************" + compact[len(compact)-4:]
	}
	if len(text) > 80 {
		return text[:76] + "…"
	}
	return text
}

func RenderSARIF(doc map[string]any) string {
	findings := asMaps(doc["findings"])
	crawler, _ := doc["crawler"].(map[string]any)
	name, ver := "shroodler", "0.1.0"
	if crawler != nil {
		if n := str(crawler["name"]); n != "" {
			name = n
		}
		if v := str(crawler["version"]); v != "" {
			ver = v
		}
	}
	seen := map[string]bool{}
	rules := make([]map[string]any, 0)
	results := make([]map[string]any, 0)
	for _, f := range findings {
		id := str(f["id"])
		if id == "" {
			id = "finding"
		}
		if !seen[id] {
			seen[id] = true
			desc := str(f["description"])
			if desc == "" {
				desc = id
			}
			rules = append(rules, map[string]any{
				"id":               id,
				"shortDescription": map[string]any{"text": id},
				"fullDescription":  map[string]any{"text": desc},
			})
		}
		uri := str(f["url"])
		if uri == "" {
			uri = str(doc["target"])
		}
		if uri == "" {
			uri = "about:blank"
		}
		level := sarifLevel[str(f["severity"])]
		if level == "" {
			level = "note"
		}
		msg := str(f["description"])
		if msg == "" {
			msg = id
		}
		results = append(results, map[string]any{
			"ruleId": id,
			"level":  level,
			"message": map[string]any{
				"text": msg,
			},
			"locations": []any{
				map[string]any{
					"physicalLocation": map[string]any{
						"artifactLocation": map[string]any{"uri": uri},
					},
				},
			},
		})
	}
	payload := map[string]any{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []any{
			map[string]any{
				"tool": map[string]any{
					"driver": map[string]any{
						"name":    name,
						"version": ver,
						"rules":   rules,
					},
				},
				"results": results,
			},
		},
	}
	b, _ := json.MarshalIndent(payload, "", "  ")
	return string(b) + "\n"
}

func RenderMarkdown(doc map[string]any) string {
	findings := asMaps(doc["findings"])
	crawler, _ := doc["crawler"].(map[string]any)
	name, version, mode := "", "", ""
	if crawler != nil {
		name = str(crawler["name"])
		version = str(crawler["version"])
		mode = str(crawler["mode"])
	}
	pages := asMaps(doc["pages"])
	var b strings.Builder
	b.WriteString("# Shroodler report\n\n")
	fmt.Fprintf(&b, "Target: `%s`\n", str(doc["target"]))
	fmt.Fprintf(&b, "Crawler: %s %s (%s)\n", name, version, mode)
	fmt.Fprintf(&b, "%d pages · %d findings\n\n", len(pages), len(findings))
	if len(findings) == 0 {
		b.WriteString("No findings.\n")
		return b.String()
	}
	grouped := map[string][]map[string]any{}
	for _, f := range findings {
		sev := str(f["severity"])
		if sev == "" {
			sev = "info"
		}
		grouped[sev] = append(grouped[sev], f)
	}
	order := append([]string{}, severityOrder...)
	for sev := range grouped {
		known := false
		for _, s := range severityOrder {
			if s == sev {
				known = true
				break
			}
		}
		if !known {
			order = append(order, sev)
		}
	}
	for _, sev := range order {
		rows := grouped[sev]
		if len(rows) == 0 {
			continue
		}
		fmt.Fprintf(&b, "## %s\n\n", sev)
		for _, f := range rows {
			id := str(f["id"])
			if id == "" {
				id = "finding"
			}
			fmt.Fprintf(&b, "### `%s`\n\n", id)
			fmt.Fprintf(&b, "- URL: `%s`\n", str(f["url"]))
			fmt.Fprintf(&b, "- Description: %s\n", str(f["description"]))
			if ev := FormatEvidence(f["evidence"]); ev != "" {
				fmt.Fprintf(&b, "- Evidence: `%s`\n", ev)
			}
			b.WriteString("\n")
		}
	}
	return b.String()
}
