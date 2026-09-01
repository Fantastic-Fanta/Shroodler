package urls

import "testing"

func TestNormalizeAndKeys(t *testing.T) {
	if !IsLocal("http://127.0.0.1:8081/") || !IsLocal("http://app1.local/") {
		t.Fatal("local")
	}
	if IsLocal("http://example.com/") {
		t.Fatal("remote")
	}
	n := Normalize("http://127.0.0.1/a", "../b#frag")
	if n == "" {
		t.Fatal("norm")
	}
	if Normalize("http://127.0.0.1/", "javascript:alert(1)") != "" {
		t.Fatal("js")
	}
	k1 := CanonicalKey("http://127.0.0.1/x/?b=2&a=1")
	k2 := CanonicalKey("http://127.0.0.1/x?a=1&b=2")
	if k1 != k2 {
		t.Fatalf("%s vs %s", k1, k2)
	}
	if PathOf("http://127.0.0.1/login") != "/login" {
		t.Fatal(PathOf("http://127.0.0.1/login"))
	}
	qn := QueryNames("http://127.0.0.1/?z=1&a=2")
	if len(qn) != 2 {
		t.Fatal(qn)
	}
	if Origin("http://127.0.0.1:8081/x") != "http://127.0.0.1:8081" {
		t.Fatal(Origin("http://127.0.0.1:8081/x"))
	}
	if !SameOrigin("http://127.0.0.1/a", "http://127.0.0.1/b") {
		t.Fatal("same")
	}
}
