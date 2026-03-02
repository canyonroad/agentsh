package api

import (
	"testing"

	"github.com/agentsh/agentsh/internal/session"
)

func TestResolveWorkingDir_RealPaths(t *testing.T) {
	m := session.NewManager(10)
	ws := t.TempDir()

	s, err := m.CreateWithID("test-exec-real", ws, "default")
	if err != nil {
		t.Fatal(err)
	}
	s.SetRealPaths(true)

	// Absolute path under workspace
	real, err := resolveWorkingDir(s, ws+"/subdir")
	if err != nil {
		t.Fatalf("resolveWorkingDir: %v", err)
	}
	if real == "" {
		t.Error("expected non-empty resolved path")
	}
}

func TestResolveWorkingDir_RealPaths_OutsideWorkspace(t *testing.T) {
	m := session.NewManager(10)
	ws := t.TempDir()

	s, err := m.CreateWithID("test-exec-outside", ws, "default")
	if err != nil {
		t.Fatal(err)
	}
	s.SetRealPaths(true)

	// Outside workspace should pass through
	real, err := resolveWorkingDir(s, "/tmp")
	if err != nil {
		t.Fatalf("resolveWorkingDir: %v", err)
	}
	if real != "/tmp" {
		t.Errorf("real = %q, want /tmp", real)
	}
}

func TestResolveWorkingDir_Default_OutsidePassthrough(t *testing.T) {
	m := session.NewManager(10)
	ws := t.TempDir()

	s, err := m.CreateWithID("test-exec-default", ws, "default")
	if err != nil {
		t.Fatal(err)
	}

	// Outside workspace paths pass through for policy/seccomp enforcement
	real, err := resolveWorkingDir(s, "/etc")
	if err != nil {
		t.Fatalf("resolveWorkingDir: %v", err)
	}
	if real != "/etc" {
		t.Errorf("real = %q, want /etc", real)
	}
}
