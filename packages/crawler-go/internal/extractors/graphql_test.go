package extractors

import (
	"strconv"
	"strings"
	"testing"
)

func TestLooksLikeGraphQL(t *testing.T) {
	if !LooksLikeGraphQL(`{"data":{"__typename":"Query"}}`) {
		t.Fatal("typename")
	}
	if !LooksLikeGraphQL(`{"errors":[{"message":"syntax"}]}`) {
		t.Fatal("errors")
	}
	for _, body := range []string{
		"",
		"not json",
		`{"ok":true}`,
		`{"data":{"users":[]}}`,
		`{"data":["x"]}`,
		`{"errors":"nope"}`,
		`{"errors":[{"code":1}]}`,
	} {
		if LooksLikeGraphQL(body) {
			t.Fatalf("false positive on %s", body)
		}
	}
}

func TestParseGraphQLSchemaTypes(t *testing.T) {
	body := `{"data":{"__schema":{"types":[{"name":"Query"},{"name":"HiddenNote"},{"name":"Query"},{"name":1},{"name":"String"}]}}}`
	names := ParseGraphQLSchemaTypes(body)
	if len(names) != 3 || names[0] != "Query" || names[1] != "HiddenNote" || names[2] != "String" {
		t.Fatalf("%v", names)
	}
	if len(ParseGraphQLSchemaTypes(`{"data":{}}`)) != 0 {
		t.Fatal("empty schema")
	}
	if len(ParseGraphQLSchemaTypes("nope")) != 0 {
		t.Fatal("garbage")
	}
	many := make([]string, 12)
	for i := range many {
		many[i] = "T" + strconv.Itoa(i)
	}
	shown := FormatGraphQLTypes(many)
	if !strings.Contains(shown, "T0") || !strings.Contains(shown, "T7") || strings.Contains(shown, "T8") {
		t.Fatalf("truncate %s", shown)
	}
	if !strings.Contains(shown, "+4 more") {
		t.Fatalf("count %s", shown)
	}
}
