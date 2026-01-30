//go:build darwin || linux

package main

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

func TestRlimitExecSetsLimit(t *testing.T) {
	wrapper := buildWrapper(t)

	// Run wrapper with a command that prints its rlimit
	limit := uint64(128 * 1024 * 1024) // 128MB

	cmd := exec.Command(wrapper, "sh", "-c", "ulimit -v")
	cmd.Env = append(os.Environ(), "AGENTSH_RLIMIT_AS="+strconv.FormatUint(limit, 10))

	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("wrapper failed: %v", err)
	}

	// ulimit -v returns limit in KB
	expectedKB := limit / 1024
	outputStr := strings.TrimSpace(string(output))
	actualKB, err := strconv.ParseUint(outputStr, 10, 64)
	if err != nil {
		// Some systems may return "unlimited" if limit is very high
		t.Logf("ulimit output: %q", outputStr)
		t.Skipf("could not parse ulimit output: %v", err)
	}

	if actualKB != expectedKB {
		t.Errorf("rlimit = %d KB, want %d KB", actualKB, expectedKB)
	}
}

func TestRlimitExecNoLimit(t *testing.T) {
	wrapper := buildWrapper(t)

	// Run without AGENTSH_RLIMIT_AS - should work normally
	cmd := exec.Command(wrapper, "echo", "hello")
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("wrapper failed: %v", err)
	}

	if !strings.Contains(string(output), "hello") {
		t.Errorf("output = %q, want to contain 'hello'", output)
	}
}

func TestRlimitExecCommandNotFound(t *testing.T) {
	wrapper := buildWrapper(t)

	cmd := exec.Command(wrapper, "nonexistent-command-12345")
	err := cmd.Run()

	if err == nil {
		t.Fatal("expected error for nonexistent command")
	}

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected ExitError, got %T", err)
	}

	if exitErr.ExitCode() != 127 {
		t.Errorf("exit code = %d, want 127", exitErr.ExitCode())
	}
}

func TestRlimitExecInvalidLimit(t *testing.T) {
	wrapper := buildWrapper(t)

	cmd := exec.Command(wrapper, "echo", "test")
	cmd.Env = append(os.Environ(), "AGENTSH_RLIMIT_AS=notanumber")

	err := cmd.Run()
	if err == nil {
		t.Fatal("expected error for invalid limit")
	}

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected ExitError, got %T", err)
	}

	if exitErr.ExitCode() != 1 {
		t.Errorf("exit code = %d, want 1", exitErr.ExitCode())
	}
}

func TestRlimitExecNoArgs(t *testing.T) {
	wrapper := buildWrapper(t)

	cmd := exec.Command(wrapper)
	err := cmd.Run()

	if err == nil {
		t.Fatal("expected error for no args")
	}

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected ExitError, got %T", err)
	}

	if exitErr.ExitCode() != 1 {
		t.Errorf("exit code = %d, want 1", exitErr.ExitCode())
	}
}

func buildWrapper(t *testing.T) string {
	t.Helper()

	tmpDir := t.TempDir()
	wrapper := tmpDir + "/agentsh-rlimit-exec"

	cmd := exec.Command("go", "build", "-o", wrapper, ".")
	cmd.Dir = "."
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build wrapper: %v\n%s", err, output)
	}

	return wrapper
}
