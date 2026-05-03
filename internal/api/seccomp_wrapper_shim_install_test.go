//go:build linux && cgo

package api

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestShimInstall_SiblingProcessTree starts an in-process agentsh test
// server with Landlock denying reads of a tempdir directory. It builds and
// runs the shim from a process tree that is NOT a child of the test
// server (mirroring the sandbox-SDK pattern from issues #267 + #268).
// Asserts the inner read of the deny target is blocked even though the
// shim is in a different process tree.
//
// We use a tempdir-based deny target instead of /etc/shadow because the
// latter is already 0600 root:root in most test environments, so a read
// attempt fails on Unix DAC alone — the test would pass even with no
// agentsh enforcement (false positive).
func TestShimInstall_SiblingProcessTree(t *testing.T) {
	if !landlockSupported(t) {
		t.Skip("Landlock not supported in this environment")
	}
	if !seccompUserNotifySupported(t) {
		t.Skip("seccomp user-notify not supported in this environment")
	}
	if !cgoAvailable() {
		t.Skip("cgo not available — cannot build agentsh-unixwrap")
	}

	// Build binaries first — skip early if build environment doesn't support cgo.
	wrapPath := buildWrapBinary(t)
	shimPath := buildShimBinary(t)

	// Create deny target: a file in its own tempdir.  The test server will
	// deny all reads from that directory via Landlock.
	denyDir := t.TempDir()
	denyFile := filepath.Join(denyDir, "secret.txt")
	const sentinel = "SHOULD_NOT_LEAK_4F8A2D3B"
	if err := os.WriteFile(denyFile, []byte(sentinel), 0o644); err != nil {
		t.Fatal(err)
	}

	// Sanity check: without agentsh, the test user can read the file.
	if _, err := os.ReadFile(denyFile); err != nil {
		t.Fatalf("environment check failed: test user cannot read %s without policy: %v",
			denyFile, err)
	}

	// Start the in-process test server.
	spec := startTestServerWithLandlockDeny(t, denyFile)

	// Create bash.real symlink next to the shim binary so it can resolve the
	// real shell.  The shim is named "bash", so it looks for "bash.real".
	shimDir := filepath.Dir(shimPath)
	bashReal := filepath.Join(shimDir, "bash.real")
	realBash, err := exec.LookPath("bash")
	if err != nil {
		realBash = "/bin/bash"
	}
	if _, statErr := os.Stat(realBash); statErr != nil {
		t.Skipf("bash not found at %s: %v", realBash, statErr)
	}
	if err := os.Symlink(realBash, bashReal); err != nil {
		t.Fatalf("symlink bash.real: %v", err)
	}

	// Set up a temp shim.conf root pointing the shim at shim_install=on.
	// Using the shimtest build tag, AGENTSH_SHIM_CONF_ROOT overrides the
	// config root so we control the shim.conf content.
	confRoot := t.TempDir()
	confDir := filepath.Join(confRoot, "etc", "agentsh")
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatalf("mkdir shim conf dir: %v", err)
	}
	// shim_install=on (env AGENTSH_SHIM_INSTALL=on also works and takes
	// precedence, but we set both for defence-in-depth).
	shimConfContent := "shim_install=on\n"
	if err := os.WriteFile(filepath.Join(confDir, "shim.conf"), []byte(shimConfContent), 0o644); err != nil {
		t.Fatalf("write shim.conf: %v", err)
	}

	// Build the environment for the shim subprocess.  agentsh-unixwrap must
	// be on PATH so the wrap-init response (which returns its path) is resolvable.
	wrapDir := filepath.Dir(wrapPath)
	testPATH := wrapDir + ":" + os.Getenv("PATH")

	env := append(os.Environ(),
		"AGENTSH_SERVER="+spec.srv.URL,
		"AGENTSH_SESSION_ID="+spec.sessionID,
		"AGENTSH_SHIM_INSTALL=on",
		"AGENTSH_SHIM_CONF_ROOT="+confRoot,
		"PATH="+testPATH,
		// Debug output so test logs capture what the shim does.
		"AGENTSH_SHIM_DEBUG=1",
	)
	// Strip AGENTSH_IN_SESSION to prevent the recursion guard from bypassing
	// the kernelinstall branch.
	env = filterEnv(env, "AGENTSH_IN_SESSION")

	cmd := exec.CommandContext(context.Background(), shimPath, "-c", "cat "+denyFile)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	t.Logf("shim output:\n%s", out)

	if err == nil {
		t.Fatalf("expected non-zero exit (deny target read should be blocked), got 0; output:\n%s", out)
	}
	if strings.Contains(string(out), sentinel) {
		t.Fatalf("deny target contents leaked; Landlock filter not enforced:\n%s", out)
	}
	t.Logf("PASS: shim exited non-zero and sentinel did not appear in output")
}

// filterEnv returns a copy of env with all entries that start with key= removed.
func filterEnv(env []string, key string) []string {
	prefix := key + "="
	out := make([]string, 0, len(env))
	for _, e := range env {
		if !strings.HasPrefix(e, prefix) {
			out = append(out, e)
		}
	}
	return out
}
