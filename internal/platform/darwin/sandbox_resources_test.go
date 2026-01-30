//go:build darwin && cgo

package darwin

import (
	"context"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/platform"
)

// sandboxExecWorks tests if sandbox-exec actually works (not just exists).
// On some macOS systems (like CI runners), sandbox-exec may exist but be
// restricted from running due to SIP or other security policies.
func sandboxExecWorks(t *testing.T, m *SandboxManager) bool {
	t.Helper()
	if !m.Available() {
		return false
	}

	// Try a simple execution to see if sandbox-exec actually works
	sb, err := m.Create(platform.SandboxConfig{
		Name:          "sandbox-test-probe",
		WorkspacePath: t.TempDir(),
	})
	if err != nil {
		return false
	}
	defer sb.Close()

	result, err := sb.Execute(context.Background(), "true")
	if err != nil {
		return false
	}
	return result.ExitCode == 0
}

func TestSandboxExecuteWithResources(t *testing.T) {
	m := NewSandboxManager()
	if !sandboxExecWorks(t, m) {
		t.Skip("sandbox-exec not functional on this system")
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

	// Verify output
	output := strings.TrimSpace(string(result.Stdout))
	if output != "hello" {
		t.Errorf("expected stdout 'hello', got %q", output)
	}
}

func TestSandboxExecuteWithResources_NilHandle(t *testing.T) {
	m := NewSandboxManager()
	if !sandboxExecWorks(t, m) {
		t.Skip("sandbox-exec not functional on this system")
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
