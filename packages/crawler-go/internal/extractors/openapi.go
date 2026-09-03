package extractors

import (
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

var OpenAPIProbePaths = []string{
	"/openapi.json",
	"/swagger.json",
	"/api-docs",
	"/openapi.yaml",
	"/swagger.yaml",
}

func IsOpenAPIProbePath(path string) bool {
	for _, p := range OpenAPIProbePaths {
		if path == p {
			return true
		}
	}
	return false
}

func ParseOpenAPIPaths(body string) []string {
	obj := loadSpec(body)
	if obj == nil {
		return nil
	}
	raw := asStringMap(obj["paths"])
	if raw == nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for key := range raw {
		p := strings.TrimSpace(key)
		if !strings.HasPrefix(p, "/") || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

func asStringMap(v any) map[string]any {
	switch m := v.(type) {
	case map[string]any:
		return m
	case map[any]any:
		out := map[string]any{}
		for k, val := range m {
			sk, ok := k.(string)
			if !ok {
				continue
			}
			out[sk] = val
		}
		return out
	default:
		return nil
	}
}

func loadSpec(body string) map[string]any {
	if strings.TrimSpace(body) == "" {
		return nil
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(body), &obj); err != nil {
		obj = nil
		if err := yaml.Unmarshal([]byte(body), &obj); err != nil || obj == nil {
			return nil
		}
	}
	if !isOpenAPI(obj) {
		return nil
	}
	return obj
}

func isOpenAPI(obj map[string]any) bool {
	if asStringMap(obj["paths"]) == nil {
		return false
	}
	if v, ok := obj["openapi"]; ok {
		return strings.HasPrefix(fmt.Sprint(v), "3")
	}
	if v, ok := obj["swagger"]; ok {
		return strings.HasPrefix(fmt.Sprint(v), "2")
	}
	return false
}
