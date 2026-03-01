package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRealPathsConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfgPath, []byte(`
sessions:
  real_paths: true
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Sessions.RealPaths {
		t.Fatal("expected sessions.real_paths to be true")
	}
}

func TestRealPathsConfig_DefaultFalse(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfgPath, []byte(`
sessions:
  max_sessions: 5
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Sessions.RealPaths {
		t.Fatal("expected sessions.real_paths to default to false")
	}
}
