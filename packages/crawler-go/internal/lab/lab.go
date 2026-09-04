package lab

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type Suppression struct {
	ID     string `json:"id" yaml:"id"`
	URL    string `json:"url" yaml:"url"`
	Reason string `json:"reason" yaml:"reason"`
}

type suppressFile struct {
	Suppressions []Suppression `yaml:"suppressions" json:"suppressions"`
}

func PathOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Path == "" {
		return "/"
	}
	return u.Path
}

func GlobMatch(pattern, value string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	escaped := regexp.QuoteMeta(pattern)
	escaped = strings.ReplaceAll(escaped, `\*`, ".*")
	escaped = strings.ReplaceAll(escaped, `\?`, ".")
	re, err := regexp.Compile("^" + escaped + "$")
	if err != nil {
		return false
	}
	return re.MatchString(value)
}

func ParseSuppressions(raw string) []Suppression {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var rows []Suppression
	if strings.HasPrefix(raw, "[") || strings.HasPrefix(raw, "{") {
		var file suppressFile
		if err := json.Unmarshal([]byte(raw), &file); err == nil && len(file.Suppressions) > 0 {
			rows = file.Suppressions
		} else {
			_ = json.Unmarshal([]byte(raw), &rows)
		}
	} else {
		var file suppressFile
		if yaml.Unmarshal([]byte(raw), &file) == nil {
			rows = file.Suppressions
		}
	}
	out := make([]Suppression, 0, len(rows))
	for _, r := range rows {
		if r.ID == "" {
			r.ID = "*"
		}
		if r.URL == "" {
			r.URL = "*"
		}
		out = append(out, r)
	}
	return out
}

func LoadSuppressions(path string) []Suppression {
	if path == "" {
		if _, err := os.Stat(".shroodlerignore"); err != nil {
			return nil
		}
		path = ".shroodlerignore"
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return ParseSuppressions(string(b))
}

func FindingSuppressed(id, findingURL string, rules []Suppression) bool {
	path := PathOf(findingURL)
	for _, r := range rules {
		if r.ID != "*" && r.ID != id {
			continue
		}
		if GlobMatch(r.URL, path) || GlobMatch(r.URL, findingURL) {
			return true
		}
	}
	return false
}

func FilterFindings(findings []map[string]any, rules []Suppression) []map[string]any {
	if len(rules) == 0 {
		return findings
	}
	out := make([]map[string]any, 0, len(findings))
	for _, f := range findings {
		id := fmt.Sprint(f["id"])
		u := fmt.Sprint(f["url"])
		if !FindingSuppressed(id, u, rules) {
			out = append(out, f)
		}
	}
	return out
}

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

func BaselineFromDoc(doc map[string]any, name string, rules []Suppression) map[string]any {
	pages := asMaps(doc["pages"])
	findings := FilterFindings(asMaps(doc["findings"]), rules)
	pageSet := map[string]struct{}{}
	forms := map[string]map[string]struct{}{}
	for _, p := range pages {
		path := PathOf(fmt.Sprint(p["url"]))
		pageSet[path] = struct{}{}
		for _, form := range asMaps(p["forms"]) {
			for _, field := range asMaps(form["fields"]) {
				n := fmt.Sprint(field["name"])
				if n == "" || n == "<nil>" {
					continue
				}
				if forms[path] == nil {
					forms[path] = map[string]struct{}{}
				}
				forms[path][n] = struct{}{}
			}
		}
	}
	expectedPages := make([]any, 0, len(pageSet))
	pageList := make([]string, 0, len(pageSet))
	for p := range pageSet {
		pageList = append(pageList, p)
	}
	sort.Strings(pageList)
	for _, p := range pageList {
		expectedPages = append(expectedPages, p)
	}
	formKeys := make([]string, 0, len(forms))
	for path := range forms {
		formKeys = append(formKeys, path)
	}
	sort.Strings(formKeys)
	orderedForms := map[string]any{}
	for _, path := range formKeys {
		names := forms[path]
		list := make([]string, 0, len(names))
		for n := range names {
			list = append(list, n)
		}
		sort.Strings(list)
		arr := make([]any, 0, len(list))
		for _, n := range list {
			arr = append(arr, n)
		}
		orderedForms[path] = arr
	}
	type pair struct{ id, url string }
	pairs := make([]pair, 0, len(findings))
	for _, f := range findings {
		pairs = append(pairs, pair{id: fmt.Sprint(f["id"]), url: PathOf(fmt.Sprint(f["url"]))})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].id != pairs[j].id {
			return pairs[i].id < pairs[j].id
		}
		return pairs[i].url < pairs[j].url
	})
	expectedFindings := make([]any, 0, len(pairs))
	for _, p := range pairs {
		expectedFindings = append(expectedFindings, map[string]any{"id": p.id, "url": p.url})
	}
	target := fmt.Sprint(doc["target"])
	if target == "<nil>" {
		target = ""
	}
	app := name
	if app == "" {
		app = target
	}
	if app == "" {
		app = "local-app"
	}
	return map[string]any{
		"target_app":         app,
		"target":             target,
		"expected_pages":     expectedPages,
		"expected_forms":     orderedForms,
		"expected_findings":  expectedFindings,
		"expected_not_found": []any{},
	}
}

type DiffOutcome struct {
	Errors   []string
	Resolved []string
}

func findingKey(item map[string]any) string {
	return fmt.Sprint(item["id"]) + "|" + PathOf(fmt.Sprint(item["url"]))
}

func Diff(actual, expected map[string]any, pagesOnly, gate bool, rules []Suppression) DiffOutcome {
	var out DiffOutcome
	actualPaths := map[string]bool{}
	for _, p := range asMaps(actual["pages"]) {
		actualPaths[PathOf(fmt.Sprint(p["url"]))] = true
	}
	if !gate {
		if exp, ok := expected["expected_pages"].([]any); ok {
			for _, p := range exp {
				ps := fmt.Sprint(p)
				if !actualPaths[ps] {
					out.Errors = append(out.Errors, "missing page "+ps)
				}
			}
		}
	}
	if pagesOnly {
		return out
	}
	visible := FilterFindings(asMaps(actual["findings"]), rules)
	actualF := map[string]bool{}
	for _, f := range visible {
		actualF[findingKey(f)] = true
	}
	expectedKeys := map[string]bool{}
	if exp, ok := expected["expected_findings"].([]any); ok {
		for _, f := range exp {
			m, _ := f.(map[string]any)
			if m == nil {
				continue
			}
			k := findingKey(m)
			expectedKeys[k] = true
			if actualF[k] {
				continue
			}
			id := fmt.Sprint(m["id"])
			path := PathOf(fmt.Sprint(m["url"]))
			if gate {
				out.Resolved = append(out.Resolved, "resolved "+id+" at "+path)
			} else {
				out.Errors = append(out.Errors, "missing finding "+id+" at "+path)
			}
		}
	}
	if nf, ok := expected["expected_not_found"].([]any); ok {
		for _, f := range nf {
			m, _ := f.(map[string]any)
			if m == nil {
				continue
			}
			if actualF[findingKey(m)] {
				out.Errors = append(out.Errors, "unexpected finding "+fmt.Sprint(m["id"])+" at "+PathOf(fmt.Sprint(m["url"])))
			}
		}
	}
	if gate {
		for _, f := range visible {
			k := findingKey(f)
			if !expectedKeys[k] {
				out.Errors = append(out.Errors, "new finding "+fmt.Sprint(f["id"])+" at "+PathOf(fmt.Sprint(f["url"])))
			}
		}
		return out
	}
	forms, _ := expected["expected_forms"].(map[string]any)
	pagesByPath := map[string]map[string]any{}
	for _, p := range asMaps(actual["pages"]) {
		pagesByPath[PathOf(fmt.Sprint(p["url"]))] = p
	}
	for path, raw := range forms {
		page := pagesByPath[path]
		if page == nil {
			out.Errors = append(out.Errors, "missing page for forms "+path)
			continue
		}
		actualFields := map[string]bool{}
		for _, form := range asMaps(page["forms"]) {
			for _, field := range asMaps(form["fields"]) {
				actualFields[fmt.Sprint(field["name"])] = true
			}
		}
		var names []any
		switch t := raw.(type) {
		case []any:
			names = t
		}
		for _, n := range names {
			ns := fmt.Sprint(n)
			if !actualFields[ns] {
				out.Errors = append(out.Errors, "missing form field "+ns+" on "+path)
			}
		}
	}
	return out
}

func WriteJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if path == "" {
		fmt.Println(string(b))
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		// ignore mkdir of .
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
