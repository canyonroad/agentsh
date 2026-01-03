//go:build windows

package windows

import (
	"context"
	"testing"

	"github.com/agentsh/agentsh/internal/platform"
)

func TestSandboxWithAppContainer(t *testing.T) {
	if !isAdmin() {
		t.Skip("requires admin privileges")
	}

	mgr := NewSandboxManager()
	if !mgr.Available() {
		t.Skip("sandbox not available")
	}

	config := platform.SandboxConfig{
		Name:          "test-sandbox",
		WorkspacePath: t.TempDir(),
		WindowsOptions: &platform.WindowsSandboxOptions{
			UseAppContainer:         true,
			UseMinifilter:           false, // Skip minifilter for this test
			FailOnAppContainerError: true,
		},
	}

	sandbox, err := mgr.Create(config)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	defer sandbox.Close()

	result, err := sandbox.Execute(context.Background(), "cmd.exe", "/c", "echo", "test")
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if result.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", result.ExitCode)
	}
}

func TestSandboxWithoutAppContainer(t *testing.T) {
	mgr := NewSandboxManager()
	if !mgr.Available() {
		t.Skip("sandbox not available")
	}

	config := platform.SandboxConfig{
		Name:          "test-sandbox-no-container",
		WorkspacePath: t.TempDir(),
		WindowsOptions: &platform.WindowsSandboxOptions{
			UseAppContainer: false,
			UseMinifilter:   false,
		},
	}

	sandbox, err := mgr.Create(config)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	defer sandbox.Close()

	result, err := sandbox.Execute(context.Background(), "cmd.exe", "/c", "echo", "hello")
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if result.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", result.ExitCode)
	}
}

func TestSandboxClose(t *testing.T) {
	mgr := NewSandboxManager()
	if !mgr.Available() {
		t.Skip("sandbox not available")
	}

	config := platform.SandboxConfig{
		Name:          "test-sandbox-close",
		WorkspacePath: t.TempDir(),
		WindowsOptions: &platform.WindowsSandboxOptions{
			UseAppContainer: false,
			UseMinifilter:   false,
		},
	}

	sandbox, err := mgr.Create(config)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Close should succeed
	if err := sandbox.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}

	// Execute after close should fail
	_, err = sandbox.Execute(context.Background(), "cmd.exe", "/c", "echo", "test")
	if err == nil {
		t.Error("expected error when executing after close")
	}
}

func TestSandboxAppContainerCleanup(t *testing.T) {
	if !isAdmin() {
		t.Skip("requires admin privileges")
	}

	mgr := NewSandboxManager()
	if !mgr.Available() {
		t.Skip("sandbox not available")
	}

	config := platform.SandboxConfig{
		Name:          "test-sandbox-cleanup",
		WorkspacePath: t.TempDir(),
		WindowsOptions: &platform.WindowsSandboxOptions{
			UseAppContainer:         true,
			UseMinifilter:           false,
			FailOnAppContainerError: true,
		},
	}

	sandbox, err := mgr.Create(config)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Close should cleanup AppContainer
	if err := sandbox.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}

	// Double close should be idempotent
	if err := sandbox.Close(); err != nil {
		t.Errorf("Double close failed: %v", err)
	}
}

func TestSandboxIsolationLevel(t *testing.T) {
	mgr := NewSandboxManager()

	// When AppContainer is available, isolation should be Partial
	if mgr.Available() {
		if mgr.IsolationLevel() != platform.IsolationPartial {
			t.Errorf("expected IsolationPartial when available, got %v", mgr.IsolationLevel())
		}
	}
}
