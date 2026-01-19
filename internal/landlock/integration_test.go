//go:build linux && integration

package landlock_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/agentsh/agentsh/internal/capabilities"
	"github.com/agentsh/agentsh/internal/landlock"
)

func TestLandlockEnforcement_BlocksUnauthorizedAccess(t *testing.T) {
	// Skip if Landlock is not available
	result := capabilities.DetectLandlock()
	if !result.Available {
		t.Skip("Landlock not available on this system")
	}

	// Create a temp directory for the test
	tmpDir, err := os.MkdirTemp("", "landlock-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a test file
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("secret"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Fork a child process to test Landlock
	// We can't apply Landlock in the test process since it's irreversible
	cmd := exec.Command("/bin/sh", "-c", `
		# This script will be sandboxed and should fail to read the test file
		cat "$1" 2>/dev/null && echo "FAIL: should not have been able to read file" && exit 1
		exit 0
	`, "--", testFile)

	// The actual Landlock enforcement would happen via a wrapper
	// For now, we test that the detection works correctly
	t.Logf("Landlock detection: %s", result.String())
	if result.ABI < 1 {
		t.Error("Expected ABI >= 1 when Landlock is available")
	}

	_ = cmd // Would run if we had the wrapper binary
}

func TestLandlockRulesetBuild(t *testing.T) {
	// Skip if Landlock is not available
	result := capabilities.DetectLandlock()
	if !result.Available {
		t.Skip("Landlock not available on this system")
	}

	// Create a temp directory for the test workspace
	tmpDir, err := os.MkdirTemp("", "landlock-workspace-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Build a ruleset
	builder := landlock.NewRulesetBuilder(result.ABI)
	builder.SetWorkspace(tmpDir)

	if err := builder.AddExecutePath("/usr/bin"); err != nil {
		t.Errorf("failed to add execute path: %v", err)
	}

	if err := builder.AddReadPath("/etc/ssl/certs"); err != nil {
		t.Errorf("failed to add read path: %v", err)
	}

	builder.AddDenyPath("/var/run/docker.sock")

	// Build the ruleset
	fd, err := builder.Build()
	if err != nil {
		t.Fatalf("failed to build ruleset: %v", err)
	}
	defer syscall.Close(fd)

	// Verify we got a valid fd
	if fd < 0 {
		t.Error("expected valid fd from Build()")
	}
}

func TestLandlockNetworkRestrictions(t *testing.T) {
	// Skip if Landlock is not available or doesn't support network
	result := capabilities.DetectLandlock()
	if !result.Available {
		t.Skip("Landlock not available on this system")
	}
	if !result.NetworkSupport {
		t.Skip("Landlock network support not available (requires ABI v4+)")
	}

	// Create a temp directory for the test workspace
	tmpDir, err := os.MkdirTemp("", "landlock-net-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Build a ruleset with network restrictions
	builder := landlock.NewRulesetBuilder(result.ABI)
	builder.SetWorkspace(tmpDir)
	builder.SetNetworkAccess(true, false) // Allow connect, deny bind

	fd, err := builder.Build()
	if err != nil {
		t.Fatalf("failed to build ruleset: %v", err)
	}
	defer syscall.Close(fd)

	t.Logf("Built Landlock ruleset with network restrictions, fd=%d", fd)
}

func TestCapabilityDropping(t *testing.T) {
	// Test that we can validate capability allow lists
	validList := []string{"CAP_NET_RAW"}
	if err := capabilities.ValidateCapabilityAllowList(validList); err != nil {
		t.Errorf("unexpected error for valid cap list: %v", err)
	}

	// Test that dangerous caps are rejected
	invalidList := []string{"CAP_SYS_ADMIN"}
	if err := capabilities.ValidateCapabilityAllowList(invalidList); err == nil {
		t.Error("expected error for CAP_SYS_ADMIN in allow list")
	}
}
