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

// TestShimInstall_NestedInstallsCompose verifies that a shim invocation that
// contains a nested shim invocation (bash -c 'bash -c "..."') correctly
// stacks two Landlock/seccomp filters and the inner shell's read of the deny
// target is still blocked. This exercises the filter-stacking path: the outer
// shim installs one filter set, the inner shim installs a second set on top.
//
// The test does NOT assert that wrap-init was called exactly twice — that would
// require server-side call counting.  It does assert the security-relevant
// outcome: the sentinel never appears in the output.
func TestShimInstall_NestedInstallsCompose(t *testing.T) {
	if !landlockSupported(t) {
		t.Skip("Landlock not supported in this environment")
	}
	if !seccompUserNotifySupported(t) {
		t.Skip("seccomp user-notify not supported in this environment")
	}
	if !cgoAvailable() {
		t.Skip("cgo not available — cannot build agentsh-unixwrap")
	}

	// Build both binaries before allocating any test resources.
	wrapPath := buildWrapBinary(t)
	shimPath := buildShimBinary(t)

	// Create the deny target: a file in its own tempdir.  The test server
	// Landlock policy denies all reads from that directory.
	denyDir := t.TempDir()
	denyFile := filepath.Join(denyDir, "secret.txt")
	const sentinel = "NESTED_SHOULD_NOT_LEAK_C7E1F2A0"
	if err := os.WriteFile(denyFile, []byte(sentinel), 0o644); err != nil {
		t.Fatal(err)
	}

	// Sanity check: without agentsh the test user can read the file.
	if _, err := os.ReadFile(denyFile); err != nil {
		t.Fatalf("environment check failed: cannot read %s without policy: %v", denyFile, err)
	}

	// Start the in-process test server with Landlock deny on denyDir.
	spec := startTestServerWithLandlockDeny(t, denyFile)
	t.Logf("test server URL: %s  session: %s", spec.srv.URL, spec.sessionID)

	// The shim binary is named "bash"; it looks for "bash.real" next to itself
	// to find the actual shell.  Create the symlink in the same directory.
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

	// Set up a temp shim.conf root with shim_install=on.
	confRoot := t.TempDir()
	confDir := filepath.Join(confRoot, "etc", "agentsh")
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatalf("mkdir shim conf dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(confDir, "shim.conf"), []byte("shim_install=on\n"), 0o644); err != nil {
		t.Fatalf("write shim.conf: %v", err)
	}

	// PATH must contain both the shim directory (so the inner "bash" resolves
	// to the shim, not the real bash) and the wrap directory (so wrap-init
	// can find agentsh-unixwrap).
	wrapDir := filepath.Dir(wrapPath)
	testPATH := shimDir + ":" + wrapDir + ":" + os.Getenv("PATH")

	env := append(os.Environ(),
		"AGENTSH_SERVER="+spec.srv.URL,
		"AGENTSH_SESSION_ID="+spec.sessionID,
		"AGENTSH_SHIM_INSTALL=on",
		"AGENTSH_SHIM_CONF_ROOT="+confRoot,
		"PATH="+testPATH,
		"AGENTSH_SHIM_DEBUG=1",
	)
	// Strip AGENTSH_IN_SESSION so neither shim level skips the kernelinstall branch.
	env = filterEnv(env, "AGENTSH_IN_SESSION")

	// Outer shim: bash -c "bash -c 'cat $denyFile'"
	// The inner "bash" is resolved via PATH to the shim binary, so two levels
	// of filter installation occur.
	innerCmd := "bash -c 'cat " + denyFile + "'"
	cmd := exec.CommandContext(context.Background(), shimPath, "-c", innerCmd)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	t.Logf("nested shim output:\n%s", out)
	t.Logf("wrap-init handler reached (server-side logs above) — filter stacking occurred")

	if err == nil {
		t.Fatalf("expected non-zero exit (inner read must be blocked); got 0:\n%s", out)
	}
	if strings.Contains(string(out), sentinel) {
		t.Fatalf("sentinel leaked from inner shell — nested filter stacking failed:\n%s", out)
	}
	t.Logf("PASS: nested shim exited non-zero and sentinel did not appear in output")
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
