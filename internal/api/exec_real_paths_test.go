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

func TestResolveWorkingDir_Default_OutsideReject(t *testing.T) {
	m := session.NewManager(10)
	ws := t.TempDir()

	s, err := m.CreateWithID("test-exec-default", ws, "default")
	if err != nil {
		t.Fatal(err)
	}

	// Default /workspace mode: outside workspace paths should be rejected
	_, err = resolveWorkingDir(s, "/etc")
	if err == nil {
		t.Error("expected error for outside-workspace path in default mode")
	}
}

func TestResolveWorkingDir_RootVirtualRoot(t *testing.T) {
	m := session.NewManager(10)
	ws := t.TempDir()

	s, err := m.CreateWithID("test-exec-rootvr", ws, "default")
	if err != nil {
		t.Fatal(err)
	}
	// Simulate VirtualRoot=="/" — paths like "/etc" should be considered
	// in-root and resolved normally (not passed through as outside)
	s.VirtualRoot = "/"

	_, err = resolveWorkingDir(s, "/etc")
	if err != nil {
		t.Fatalf("resolveWorkingDir with VirtualRoot=/: %v", err)
	}
}
