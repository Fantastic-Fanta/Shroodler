package breakpoint

import "testing"

func TestParse(t *testing.T) {
	r := Parse("GET", ".*", "request")
	if r.Method != "GET" || r.Stage != "request" {
		t.Fatalf("%#v", r)
	}
}
