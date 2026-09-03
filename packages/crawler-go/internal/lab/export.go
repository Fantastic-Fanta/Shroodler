package lab

import (
	"encoding/json"
	"fmt"
	"html"
	"strings"
)

var sarifLevel = map[string]string{
	"critical": "error",
	"high":     "error",
	"medium":   "warning",
	"low":      "note",
	"info":     "note",
}

func RenderSARIF(doc map[string]any) string {
	findings := asMaps(doc["findings"])
	crawler, _ := doc["crawler"].(map[string]any)
	name, ver := "shroodler", "0.1.0"
	if crawler != nil {
		if n := fmt.Sprint(crawler["name"]); n != "" && n != "<nil>" {
			name = n
		}
		if v := fmt.Sprint(crawler["version"]); v != "" && v != "<nil>" {
			ver = v
		}
	}
	seen := map[string]bool{}
	var rules []map[string]any
	var results []map[string]any
	for _, f := range findings {
		id := fmt.Sprint(f["id"])
		if id == "" || id == "<nil>" {
			id = "finding"
		}
		if !seen[id] {
			seen[id] = true
			desc := fmt.Sprint(f["description"])
			if desc == "" || desc == "<nil>" {
				desc = id
			}
			rules = append(rules, map[string]any{
				"id":                id,
				"shortDescription":  map[string]any{"text": id},
				"fullDescription":   map[string]any{"text": desc},
			})
		}
		uri := fmt.Sprint(f["url"])
		if uri == "" || uri == "<nil>" {
			uri = fmt.Sprint(doc["target"])
		}
		sev := fmt.Sprint(f["severity"])
		level := sarifLevel[sev]
		if level == "" {
			level = "note"
		}
		msg := fmt.Sprint(f["description"])
		if msg == "" || msg == "<nil>" {
			msg = id
		}
		results = append(results, map[string]any{
			"ruleId": id,
			"level":  level,
			"message": map[string]any{"text": msg},
			"locations": []any{
				map[string]any{
					"physicalLocation": map[string]any{
						"artifactLocation": map[string]any{"uri": uri},
					},
				},
			},
		})
	}
	if rules == nil {
		rules = []map[string]any{}
	}
	if results == nil {
		results = []map[string]any{}
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

func xmlEscape(s string) string {
	return html.EscapeString(s)
}

func RenderJUnit(doc map[string]any) string {
	findings := asMaps(doc["findings"])
	tests := len(findings)
	fails := len(findings)
	if tests == 0 {
		tests = 1
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	fmt.Fprintf(&b, `<testsuite name="shroodler" tests="%d" failures="%d" errors="0">`+"\n", tests, fails)
	if len(findings) == 0 {
		b.WriteString(`  <testcase classname="shroodler" name="ok"/>` + "\n")
	}
	for _, f := range findings {
		id := fmt.Sprint(f["id"])
		u := fmt.Sprint(f["url"])
		name := strings.TrimSpace(id + " " + u)
		if name == "" {
			name = "finding"
		}
		classname := fmt.Sprint(f["category"])
		if classname == "" || classname == "<nil>" {
			classname = "finding"
		}
		msg := fmt.Sprint(f["description"])
		if msg == "" || msg == "<nil>" {
			msg = name
		}
		ev := fmt.Sprint(f["evidence"])
		if ev == "" || ev == "<nil>" {
			ev = msg
		}
		fmt.Fprintf(&b, `  <testcase classname="%s" name="%s">`+"\n", xmlEscape(classname), xmlEscape(name))
		fmt.Fprintf(&b, `    <failure message="%s">%s</failure>`+"\n", xmlEscape(msg), xmlEscape(ev))
		b.WriteString("  </testcase>\n")
	}
	b.WriteString("</testsuite>\n")
	return b.String()
}

func RenderDiffJUnit(errors []string) string {
	findings := make([]any, 0, len(errors))
	for _, e := range errors {
		findings = append(findings, map[string]any{
			"id":          "diff",
			"category":    "diff",
			"url":         "",
			"description": e,
			"evidence":    e,
		})
	}
	return RenderJUnit(map[string]any{"findings": findings})
}

func RenderDiffSARIF(errors []string) string {
	findings := make([]any, 0, len(errors))
	for _, e := range errors {
		findings = append(findings, map[string]any{
			"id":          "diff",
			"severity":    "high",
			"category":    "diff",
			"url":         "",
			"description": e,
		})
	}
	return RenderSARIF(map[string]any{
		"crawler":  map[string]any{"name": "shroodler", "version": "0.1.0"},
		"findings": findings,
	})
}
