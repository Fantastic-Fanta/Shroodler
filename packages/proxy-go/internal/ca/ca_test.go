package ca

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateExportLeafUninstall(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	if err := s.Generate(); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "pub.pem")
	if err := s.Export(out); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Leaf("127.0.0.1:443"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Leaf("example.local"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CertPEM(); err != nil {
		t.Fatal(err)
	}
	if err := s.Uninstall(false); err == nil {
		t.Fatal("need confirm")
	}
	if err := s.Uninstall(true); err != nil {
		t.Fatal(err)
	}
}

func TestLoadExistingCA(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	if err := s.Generate(); err != nil {
		t.Fatal(err)
	}
	s2 := NewStore(dir)
	if err := s2.Load(); err != nil {
		t.Fatal(err)
	}
	if err := s2.Export(filepath.Join(dir, "e.pem")); err != nil {
		t.Fatal(err)
	}
}

func TestHomeDirDefault(t *testing.T) {
	t.Setenv("SHROODLER_PROXY_HOME", "")
	_ = HomeDir()
	t.Setenv("SHROODLER_PROXY_HOME", t.TempDir())
	if HomeDir() == "" {
		t.Fatal("home")
	}
}
