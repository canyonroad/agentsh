//go:build linux

package linux

import (
	"context"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/platform"
)

func TestNewSandboxManager(t *testing.T) {
	m := NewSandboxManager()
	if m == nil {
		t.Fatal("NewSandboxManager returned nil")
	}

	// Should detect some level of isolation
	level := m.IsolationLevel()
	t.Logf("Isolation level: %s", level)
	// On most Linux systems, at least minimal isolation should be available
}

func TestSandboxManager_Available(t *testing.T) {
	m := NewSandboxManager()
	available := m.Available()
	t.Logf("Sandbox available: %v", available)
	// On most Linux systems, sandboxing should be available
}

func TestSandboxManager_Create(t *testing.T) {
	m := NewSandboxManager()
	if !m.Available() {
		t.Skip("Sandboxing not available")
	}

	cfg := platform.SandboxConfig{
		Name:          "test-sandbox",
		WorkspacePath: "/tmp",
	}

	sandbox, err := m.Create(cfg)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	defer sandbox.Close()

	if sandbox.ID() != "test-sandbox" {
		t.Errorf("ID() = %q, want %q", sandbox.ID(), "test-sandbox")
	}
}

func TestSandbox_Execute(t *testing.T) {
	m := NewSandboxManager()
	if !m.Available() {
		t.Skip("Sandboxing not available")
	}

	// Skip if isolation level is full (requires privileges for user namespace)
	if m.IsolationLevel() == platform.IsolationFull {
		t.Skip("Full isolation requires privileges")
	}

	cfg := platform.SandboxConfig{
		Name:          "exec-test",
		WorkspacePath: "/tmp",
	}

	sandbox, err := m.Create(cfg)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	defer sandbox.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := sandbox.Execute(ctx, "echo", "hello")
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	if result.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", result.ExitCode)
	}

	if string(result.Stdout) != "hello\n" {
		t.Errorf("Stdout = %q, want %q", result.Stdout, "hello\n")
	}
}

func TestSandbox_Close(t *testing.T) {
	m := NewSandboxManager()
	if !m.Available() {
		t.Skip("Sandboxing not available")
	}

	cfg := platform.SandboxConfig{
		Name: "close-test",
	}

	sandbox, err := m.Create(cfg)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Close should succeed
	if err := sandbox.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Second close should also succeed (idempotent)
	if err := sandbox.Close(); err != nil {
		t.Errorf("Second Close() error = %v", err)
	}

	// Execute after close should fail
	ctx := context.Background()
	_, err = sandbox.Execute(ctx, "echo", "test")
	if err == nil {
		t.Error("Execute() after Close() should fail")
	}
}

// Compile-time interface checks
var (
	_ platform.SandboxManager = (*SandboxManager)(nil)
	_ platform.Sandbox        = (*Sandbox)(nil)
)
