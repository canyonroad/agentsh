package envshim

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// buildShim compiles envshim.c into a .so in a temp dir.
func buildShim(t *testing.T) string {
	t.Helper()

	_, err := exec.LookPath("gcc")
	if err != nil {
		t.Skip("gcc not found; skipping envshim tests")
	}

	tmp := t.TempDir()
	out := filepath.Join(tmp, "libenvshim.so")
	// Build from the source directory (same as this test file).
	_, file, _, _ := runtime.Caller(0)
	srcDir := filepath.Dir(file)
	cmd := exec.Command("gcc", "-shared", "-fPIC", "envshim.c", "-o", out)
	cmd.Dir = srcDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("gcc build failed: %v", err)
	}
	return out
}

// Test that when AGENTSH_ENV_BLOCK_ITERATION=1, iterating env (via /usr/bin/env)
// yields an empty environment.
func TestEnvShimBlocksIteration(t *testing.T) {
	shim := buildShim(t)

	cmd := exec.Command("/usr/bin/env")
	cmd.Env = []string{
		"LD_PRELOAD=" + shim,
		"AGENTSH_ENV_BLOCK_ITERATION=1",
		"FOO=bar",
		"PATH=" + os.Getenv("PATH"),
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("env command failed: %v, output=%q", err, out.String())
	}
	got := strings.TrimSpace(out.String())
	if got != "" {
		t.Fatalf("expected empty env output when iteration blocked, got %q", got)
	}
}

// Test that without the block flag, iteration still works and shows env vars.
func TestEnvShimAllowsIterationWhenNotBlocked(t *testing.T) {
	shim := buildShim(t)

	cmd := exec.Command("/usr/bin/env")
	cmd.Env = []string{
		"LD_PRELOAD=" + shim,
		"FOO=bar",
		"PATH=" + os.Getenv("PATH"),
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("env command failed: %v, output=%q", err, out.String())
	}
	if !strings.Contains(out.String(), "FOO=bar") {
		t.Fatalf("expected env output to include FOO=bar, got %q", out.String())
	}
}
