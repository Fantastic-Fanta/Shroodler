package main

import (
	"os"
	"path/filepath"
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
}
