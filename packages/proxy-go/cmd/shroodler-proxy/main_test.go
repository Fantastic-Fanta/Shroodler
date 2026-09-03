package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCmdCA(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SHROODLER_PROXY_HOME", dir)
	if cmdCA([]string{"generate"}) != 0 {
		t.Fatal("generate")
	}
	out := filepath.Join(dir, "ca.pem")
	if cmdCA([]string{"export", "--output", out}) != 0 {
		t.Fatal("export")
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatal(err)
	}
	if cmdCA([]string{"uninstall"}) != 2 {
		t.Fatal("need --yes")
	}
	if cmdCA([]string{"uninstall", "--yes"}) != 0 {
		t.Fatal("uninstall")
	}
	if cmdCA(nil) != 2 {
		t.Fatal("usage")
	}
}

func TestCmdReplay(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SHROODLER_PROXY_HOME", dir)
	cmdCA([]string{"generate"})
	sess := filepath.Join(dir, "s.json")
	os.WriteFile(sess, []byte(`{"id":"x","request":{"method":"GET","url":"http://127.0.0.1:9/","headers":{},"body":{"encoding":"utf8","content":""}}}`), 0o644)
	// unreachable target surfaces error but should not panic
	_ = cmdReplay([]string{sess})
	out := filepath.Join(dir, "o.json")
	_ = cmdReplay([]string{sess, "--output", out, "--edit-header", "X-A=1"})
}

func TestCmdStartLoop(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SHROODLER_PROXY_HOME", dir)
	cmdCA([]string{"generate"})
	done := make(chan int, 1)
	go func() {
		done <- cmdStart([]string{"--port", "0", "--control-port", "0"})
	}()
	select {
	case <-time.After(200 * time.Millisecond):
	case code := <-done:
		if code != 0 {
			t.Fatalf("start exited %d", code)
		}
	}
}

func TestUsageAndUnknown(t *testing.T) {
	if cmdReplay(nil) != 2 {
		t.Fatal()
	}
	if run(nil) != 2 {
		t.Fatal("empty")
	}
	if run([]string{"nope"}) != 2 {
		t.Fatal("unknown")
	}
	if cmdHAR(nil) != 2 {
		t.Fatal()
	}
	if cmdHAR([]string{"nope"}) != 2 {
		t.Fatal()
	}
}

func TestCmdHARRoundTrip(t *testing.T) {
	dir := t.TempDir()
	jsonl := filepath.Join(dir, "sessions.jsonl")
	harPath := filepath.Join(dir, "out.har")
	back := filepath.Join(dir, "back.jsonl")
	line := `{"id":"abc","started_at":"2026-09-01T12:00:00Z","request":{"method":"GET","url":"http://127.0.0.1:8081/api","http_version":"HTTP/1.1","headers":{},"body":{"encoding":"utf8","content":""}},"response":{"status_code":201,"headers":{"Content-Type":"text/plain"},"body":{"encoding":"utf8","content":"created"}}}` + "\n"
	if err := os.WriteFile(jsonl, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	if cmdHAR([]string{"export", jsonl, "--output", harPath}) != 0 {
		t.Fatal("export")
	}
	if cmdHAR([]string{"import", harPath, "--output", back}) != 0 {
		t.Fatal("import")
	}
	if cmdHAR([]string{"export"}) != 2 {
		t.Fatal("missing paths")
	}
	if cmdHAR([]string{"export", jsonl, "--output"}) != 2 {
		t.Fatal("missing output path")
	}
	b, err := os.ReadFile(back)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, `"method":"GET"`) && !strings.Contains(s, `"method": "GET"`) {
		t.Fatalf("method missing: %s", s)
	}
	if !strings.Contains(s, "http://127.0.0.1:8081/api") {
		t.Fatalf("url missing: %s", s)
	}
	if !strings.Contains(s, `"status_code":201`) && !strings.Contains(s, `"status_code": 201`) {
		t.Fatalf("status missing: %s", s)
	}
}
