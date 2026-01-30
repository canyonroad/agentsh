//go:build darwin && cgo

package darwin

import (
	"context"
	"testing"

	"github.com/agentsh/agentsh/internal/platform"
)

func TestSandboxExecuteWithResources(t *testing.T) {
	m := NewSandboxManager()
	if !m.Available() {
		t.Skip("sandbox-exec not available")
	}

	sb, err := m.Create(platform.SandboxConfig{
		Name:          "test-resources",
		WorkspacePath: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	defer sb.Close()

	// Create resource handle
	rl := NewResourceLimiter()
	rh, err := rl.Apply(platform.ResourceConfig{
		Name:          "test",
		MaxCPUPercent: 80,
	})
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	defer rh.Release()

	// Execute with resources
	result, err := sb.(*Sandbox).ExecuteWithResources(
		context.Background(),
		rh.(*ResourceHandle),
		"echo", "hello",
	)
	if err != nil {
		t.Fatalf("ExecuteWithResources failed: %v", err)
	}

	if result.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", result.ExitCode)
	}
}

func TestSandboxExecuteWithResources_NilHandle(t *testing.T) {
	m := NewSandboxManager()
	if !m.Available() {
		t.Skip("sandbox-exec not available")
	}

	sb, err := m.Create(platform.SandboxConfig{
		Name:          "test-nil-handle",
		WorkspacePath: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	defer sb.Close()

	// Execute with nil resource handle should still work
	result, err := sb.(*Sandbox).ExecuteWithResources(
		context.Background(),
		nil,
		"echo", "test",
	)
	if err != nil {
		t.Fatalf("ExecuteWithResources with nil handle failed: %v", err)
	}

	if result.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", result.ExitCode)
	}
}

func TestSandboxExecuteWithResources_Closed(t *testing.T) {
	s := &Sandbox{
		id:     "test",
		closed: true,
	}

	_, err := s.ExecuteWithResources(context.Background(), nil, "echo", "hello")
	if err == nil {
		t.Error("ExecuteWithResources() should error when sandbox is closed")
	}
}

func TestSandboxSetResourceHandle(t *testing.T) {
	s := &Sandbox{id: "test"}

	// Create a mock resource handle
	rh := &ResourceHandle{
		name:     "test-handle",
		monitors: make(map[int]*cpuMonitor),
	}

	// SetResourceHandle should not panic
	s.SetResourceHandle(rh)

	// The handle is not stored on the struct, so we just verify no panic occurred
	// The method exists for API consistency and documentation purposes
}
