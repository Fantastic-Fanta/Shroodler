package extractors

import (
	"encoding/json"
	"strconv"
	"strings"
)

var GraphQLProbePaths = []string{"/graphql", "/api/graphql", "/query"}

const (
	GraphQLTypenameQuery      = `{ __typename }`
	GraphQLIntrospectionQuery = `{ __schema { types { name } } }`
	graphQLMaxTypes           = 8
	graphQLMaxTypeChars       = 200
)

func LooksLikeGraphQL(body string) bool {
	obj := parseJSONObject(body)
	if obj == nil {
		return false
	}
	if data, ok := obj["data"].(map[string]any); ok {
		if name, ok := data["__typename"].(string); ok && name != "" {
			return true
		}
	}
	errors, ok := obj["errors"].([]any)
	if !ok || len(errors) == 0 {
		return false
	}
	for _, item := range errors {
		m, ok := item.(map[string]any)
		if !ok {
			return false
		}
		if _, ok := m["message"]; !ok {
			return false
		}
	}
	return true
}

func ParseGraphQLSchemaTypes(body string) []string {
	obj := parseJSONObject(body)
	if obj == nil {
		return nil
	}
	data, _ := obj["data"].(map[string]any)
	if data == nil {
		return nil
	}
	schema, _ := data["__schema"].(map[string]any)
	if schema == nil {
		return nil
	}
	raw, _ := schema["types"].([]any)
	if raw == nil {
		return nil
	}
	seen := map[string]bool{}
	var names []string
	for _, item := range raw {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name, _ := m["name"].(string)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	return names
}

func FormatGraphQLTypes(names []string) string {
	if len(names) == 0 {
		return ""
	}
	n := len(names)
	if n > graphQLMaxTypes {
		n = graphQLMaxTypes
	}
	text := strings.Join(names[:n], ", ")
	if extra := len(names) - n; extra > 0 {
		text += " (+" + strconv.Itoa(extra) + " more)"
	}
	if len(text) > graphQLMaxTypeChars {
		return text[:graphQLMaxTypeChars-3] + "..."
	}
	return text
}

func GraphQLFindingDescription(path string, types []string) string {
	desc := "GraphQL endpoint responds at " + path
	if shown := FormatGraphQLTypes(types); shown != "" {
		desc += "; types: " + shown
	}
	return desc
}

func parseJSONObject(body string) map[string]any {
	if strings.TrimSpace(body) == "" {
		return nil
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(body), &obj); err != nil || obj == nil {
		return nil
	}
	return obj
}
