package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEngine_Limits(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yml")
	if err := os.WriteFile(path, []byte(`
version: 1
name: test
file_rules: []
network_rules: []
command_rules: []
resource_limits:
  command_timeout: 12s
  session_timeout: 34m
  idle_timeout: 56m
`), 0o644); err != nil {
		t.Fatal(err)
	}

	p, err := LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEngine(p, false)
	if err != nil {
		t.Fatal(err)
	}

	lim := e.Limits()
	if lim.CommandTimeout != 12*time.Second {
		t.Fatalf("command_timeout: expected 12s, got %s", lim.CommandTimeout)
	}
	if lim.SessionTimeout != 34*time.Minute {
		t.Fatalf("session_timeout: expected 34m, got %s", lim.SessionTimeout)
	}
	if lim.IdleTimeout != 56*time.Minute {
		t.Fatalf("idle_timeout: expected 56m, got %s", lim.IdleTimeout)
	}
}

