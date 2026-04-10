package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestResolveAgentshBin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-shim tests require Unix shell")
	}
	t.Run("uses AGENTSH_BIN when set", func(t *testing.T) {
		t.Setenv("AGENTSH_BIN", "echo")
		p, err := resolveAgentshBin()
		if err != nil {
			t.Fatalf("resolveAgentshBin() err = %v", err)
		}
		if !strings.HasSuffix(p, "/echo") {
			t.Fatalf("expected echo path, got %q", p)
		}
	})

	t.Run("falls back to PATH when env empty", func(t *testing.T) {
		t.Setenv("AGENTSH_BIN", "")
		tmp := t.TempDir()
		f := filepath.Join(tmp, "agentsh")
		if err := os.WriteFile(f, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", tmp)
		p, err := resolveAgentshBin()
		if err != nil {
			t.Fatalf("resolveAgentshBin() err = %v", err)
		}
		if p != f {
			t.Fatalf("expected %q, got %q", f, p)
		}
	})
}

func TestResolveRealShell(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-shim tests require Unix shell")
	}
	t.Run("finds sibling .real next to argv0", func(t *testing.T) {
		tmp := t.TempDir()
		shell := filepath.Join(tmp, "sh.real")
		if err := os.WriteFile(shell, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		prevArgs := os.Args
		os.Args = []string{filepath.Join(tmp, "sh"), "-c", "echo"}
		t.Cleanup(func() { os.Args = prevArgs })
		p, err := resolveRealShell("sh")
		if err != nil {
			t.Fatalf("resolveRealShell() err = %v", err)
		}
		if p != shell {
			t.Fatalf("expected %q, got %q", shell, p)
		}
	})

	t.Run("returns error when missing", func(t *testing.T) {
		prevArgs := os.Args
		os.Args = []string{"/bin/sh"}
		t.Cleanup(func() { os.Args = prevArgs })
		_, err := resolveRealShell("sh-nonexistent")
		if err == nil {
			t.Fatalf("expected error")
		}
	})

	t.Run("returns original path not symlink target", func(t *testing.T) {
		tmp := t.TempDir()

		// Create a real binary that sh.real will symlink to.
		target := filepath.Join(tmp, "dash")
		if err := os.WriteFile(target, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}

		// sh.real -> dash (symlink to another binary)
		shReal := filepath.Join(tmp, "sh.real")
		if err := os.Symlink(target, shReal); err != nil {
			t.Fatal(err)
		}

		prevArgs := os.Args
		os.Args = []string{filepath.Join(tmp, "sh"), "-c", "echo"}
		t.Cleanup(func() { os.Args = prevArgs })

		p, err := resolveRealShell("sh")
		if err != nil {
			t.Fatalf("resolveRealShell() err = %v", err)
		}
		// Must return the original sh.real path, not the resolved /dash path.
		if p != shReal {
			t.Fatalf("expected original path %q, got %q (should not resolve symlink target)", shReal, p)
		}
	})

	t.Run("skips candidate that symlinks back to shim itself", func(t *testing.T) {
		tmp := t.TempDir()

		// os.Executable() in a test returns the test binary itself.
		// Make fakeshell.real symlink to that binary so the self-loop guard fires.
		self, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}

		shReal := filepath.Join(tmp, "fakeshell.real")
		if err := os.Symlink(self, shReal); err != nil {
			t.Fatal(err)
		}

		prevArgs := os.Args
		// Use a unique name so /bin/fakeshell.real and /usr/bin/fakeshell.real won't exist.
		os.Args = []string{filepath.Join(tmp, "fakeshell"), "-c", "echo"}
		t.Cleanup(func() { os.Args = prevArgs })

		// The self-loop candidate should be skipped, resulting in an error
		// (since there are no other candidates that aren't self-loops).
		_, err = resolveRealShell("fakeshell")
		if err == nil {
			t.Fatalf("expected error when fakeshell.real symlinks back to shim, but got nil")
		}
	})
}

func TestIsMCPCommand(t *testing.T) {
	tests := []struct {
		name  string
		argv0 string
		args  []string
		want  bool
	}{
		{
			name:  "shell with mcp server",
			argv0: "/bin/sh",
			args:  []string{"-c", "npx @modelcontextprotocol/server-filesystem /workspace"},
			want:  true,
		},
		{
			name:  "shell with regular command",
			argv0: "/bin/sh",
			args:  []string{"-c", "ls -la"},
			want:  false,
		},
		{
			name:  "direct mcp server",
			argv0: "mcp-server-sqlite",
			args:  []string{"--db", "test.db"},
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isMCPCommand(tt.argv0, tt.args)
			if got != tt.want {
				t.Errorf("isMCPCommand(%q, %v) = %v, want %v", tt.argv0, tt.args, got, tt.want)
			}
		})
	}
}

// buildShim compiles the shell shim binary into dir and returns its path.
func buildShim(t *testing.T, dir string) string {
	t.Helper()
	shimBin := filepath.Join(dir, "sh")
	cmd := exec.Command("go", "build", "-tags", "shimtest", "-o", shimBin, ".")
	// Resolve the source directory relative to this test file.
	cmd.Dir = filepath.Join(srcDir(t), "cmd", "agentsh-shell-shim")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build shim: %v\n%s", err, out)
	}
	return shimBin
}

// srcDir returns the repository root by walking up from the test binary location.
func srcDir(t *testing.T) string {
	t.Helper()
	// go test sets the working directory to the package directory.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// Walk up to find go.mod
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not find repository root from %s", wd)
		}
		dir = parent
	}
}

// copyFilePath copies src to dst preserving permissions.
func copyFilePath(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatalf("open %s: %v", src, err)
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		t.Fatal(err)
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode())
	if err != nil {
		t.Fatalf("create %s: %v", dst, err)
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
}

// startFakeServer starts a TCP listener on a random port and returns the
// AGENTSH_SERVER URL. The listener is closed when the test ends. This
// satisfies the shim's server readiness gate so enforcement proceeds.
func startFakeServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start fake server: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	// Accept (and discard) connections so the dial doesn't hang.
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	return fmt.Sprintf("http://%s", ln.Addr().String())
}

func TestShimPipedStdin_PassesBinaryDataThrough(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-shim tests require Unix")
	}

	tmp := t.TempDir()
	shimBin := buildShim(t, tmp)

	// Symlink sh.real to /bin/sh so the shim can resolve it.
	// A copy would lose the macOS code signature seal and get SIGKILL'd.
	if err := os.Symlink("/bin/sh", filepath.Join(tmp, "sh.real")); err != nil {
		t.Fatal(err)
	}

	// Generate binary data with null bytes, ELF-like header, and full byte range.
	binaryData := make([]byte, 4096)
	copy(binaryData, []byte{0x7f, 'E', 'L', 'F'}) // ELF magic
	for i := 4; i < len(binaryData); i++ {
		binaryData[i] = byte(i % 256)
	}

	// Run the shim with piped stdin (non-TTY). This simulates:
	//   docker exec -i container sh -c "cat" < binary_file
	cmd := exec.Command(shimBin, "-c", "cat")
	cmd.Stdin = bytes.NewReader(binaryData)
	cmd.Env = []string{
		"PATH=/usr/bin:/bin",
		"AGENTSH_SESSION_ID=test-session",
		// agentsh is not available — if the shim tries to go through agentsh,
		// it will fail. With the non-interactive bypass, it should exec sh.real directly.
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		t.Fatalf("shim exited with error: %v\nstderr: %s", err, stderr.String())
	}

	if !bytes.Equal(stdout.Bytes(), binaryData) {
		t.Fatalf("binary data corrupted: wrote %d bytes, got %d bytes back\nfirst 16 in:  %x\nfirst 16 out: %x",
			len(binaryData), stdout.Len(), binaryData[:16], stdout.Bytes()[:min(16, stdout.Len())])
	}
}

func TestShimPipedStdin_PreservesExitCode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-shim tests require Unix")
	}

	tmp := t.TempDir()
	shimBin := buildShim(t, tmp)
	if err := os.Symlink("/bin/sh", filepath.Join(tmp, "sh.real")); err != nil {
		t.Fatal(err)
	}

	// Non-interactive: run a command that exits with code 42.
	cmd := exec.Command(shimBin, "-c", "exit 42")
	cmd.Stdin = strings.NewReader("") // piped (non-TTY)
	cmd.Env = []string{
		"PATH=/usr/bin:/bin",
		"AGENTSH_SESSION_ID=test-session",
	}

	err := cmd.Run()
	if err == nil {
		t.Fatalf("expected non-zero exit")
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("expected ExitError, got %T: %v", err, err)
	}
	if ee.ExitCode() != 42 {
		t.Fatalf("expected exit code 42, got %d", ee.ExitCode())
	}
}

func TestShimPipedStdin_StderrNotContaminated(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-shim tests require Unix")
	}

	tmp := t.TempDir()
	shimBin := buildShim(t, tmp)
	if err := os.Symlink("/bin/sh", filepath.Join(tmp, "sh.real")); err != nil {
		t.Fatal(err)
	}

	// Non-interactive: stdout and stderr should contain only what the command produces.
	cmd := exec.Command(shimBin, "-c", "echo hello && echo err >&2")
	cmd.Stdin = strings.NewReader("")
	cmd.Env = []string{
		"PATH=/usr/bin:/bin",
		"AGENTSH_SESSION_ID=test-session",
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("shim exited with error: %v\nstderr: %s", err, stderr.String())
	}

	if got := stdout.String(); got != "hello\n" {
		t.Fatalf("stdout contaminated: expected %q, got %q", "hello\n", got)
	}
	if got := stderr.String(); got != "err\n" {
		t.Fatalf("stderr contaminated: expected %q, got %q", "err\n", got)
	}
}

func TestShimConfForce_EnforcesWithoutTTY(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-shim tests require Unix")
	}

	tmp := t.TempDir()
	shimBin := buildShim(t, tmp)
	if err := os.Symlink("/bin/sh", filepath.Join(tmp, "sh.real")); err != nil {
		t.Fatal(err)
	}

	// Write shim.conf with force=true under a temp root.
	// AGENTSH_SHIM_CONF_ROOT tells the shim to read config from here.
	confDir := filepath.Join(tmp, "etc", "agentsh")
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(confDir, "shim.conf"), []byte("force=true\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Start a fake server so the readiness gate passes.
	srvURL := startFakeServer(t)

	// No AGENTSH_SHIM_FORCE env var — config file alone should trigger enforce.
	// The shim will try to find agentsh and fail, proving it didn't bypass.
	cmd := exec.Command(shimBin, "-c", "echo hello")
	cmd.Stdin = strings.NewReader("") // non-TTY
	cmd.Env = []string{
		"PATH=/usr/bin:/bin",
		"AGENTSH_SESSION_ID=test-session",
		"AGENTSH_SHIM_CONF_ROOT=" + tmp,
		"AGENTSH_SERVER=" + srvURL,
		// No AGENTSH_SHIM_FORCE — relying on config file.
		// No AGENTSH_BIN — agentsh not available, so enforce path will fail.
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	// Should fail because agentsh is not available (it tried to enforce, not bypass).
	if err == nil {
		t.Fatalf("expected error: shim should try to enforce (find agentsh) and fail, not bypass")
	}
	// Confirm it didn't bypass by checking stderr for agentsh resolution error.
	if !strings.Contains(stderr.String(), "agentsh") {
		t.Fatalf("expected agentsh-related error, got stderr: %s", stderr.String())
	}
}

func TestShimConfForce_EnvZeroCannotOverrideConfig(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-shim tests require Unix")
	}

	tmp := t.TempDir()
	shimBin := buildShim(t, tmp)
	if err := os.Symlink("/bin/sh", filepath.Join(tmp, "sh.real")); err != nil {
		t.Fatal(err)
	}

	// Write config with force=true. AGENTSH_SHIM_FORCE=0 should NOT override —
	// env can only add enforcement, never remove it.
	confDir := filepath.Join(tmp, "etc", "agentsh")
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(confDir, "shim.conf"), []byte("force=true\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Start a fake server so the readiness gate passes.
	srvURL := startFakeServer(t)

	cmd := exec.Command(shimBin, "-c", "echo hello")
	cmd.Stdin = strings.NewReader("") // non-TTY
	cmd.Env = []string{
		"PATH=/usr/bin:/bin",
		"AGENTSH_SESSION_ID=test-session",
		"AGENTSH_SHIM_CONF_ROOT=" + tmp,
		"AGENTSH_SHIM_FORCE=0",
		"AGENTSH_SERVER=" + srvURL,
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	// Config force=true should win — shim tries to enforce and fails (no agentsh).
	if err == nil {
		t.Fatalf("expected error: FORCE=0 should not override config force=true")
	}
	if !strings.Contains(stderr.String(), "agentsh") {
		t.Fatalf("expected agentsh-related error (enforce path), got stderr: %s", stderr.String())
	}
}

func TestShimConfForce_UnreadableConfigFailsClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-shim tests require Unix")
	}
	if os.Getuid() == 0 {
		t.Skip("test requires non-root")
	}

	tmp := t.TempDir()
	shimBin := buildShim(t, tmp)
	if err := os.Symlink("/bin/sh", filepath.Join(tmp, "sh.real")); err != nil {
		t.Fatal(err)
	}

	// Write shim.conf but make it unreadable. The shim should fail-closed:
	// assume force=true and try to enforce (not bypass).
	confDir := filepath.Join(tmp, "etc", "agentsh")
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(confDir, "shim.conf"), []byte("force=true\n"), 0o000); err != nil {
		t.Fatal(err)
	}

	// Start a fake server so the readiness gate passes.
	srvURL := startFakeServer(t)

	cmd := exec.Command(shimBin, "-c", "echo hello")
	cmd.Stdin = strings.NewReader("") // non-TTY
	cmd.Env = []string{
		"PATH=/usr/bin:/bin",
		"AGENTSH_SESSION_ID=test-session",
		"AGENTSH_SHIM_CONF_ROOT=" + tmp,
		"AGENTSH_SERVER=" + srvURL,
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	// Should fail because the shim tried to enforce (fail-closed), not bypass.
	if err == nil {
		t.Fatalf("expected error: unreadable config should fail-closed and try to enforce, not bypass")
	}
	if !strings.Contains(stderr.String(), "agentsh") {
		t.Fatalf("expected agentsh-related error (enforce path), got stderr: %s", stderr.String())
	}
}

// TestShimReadinessGate_ServerUnreachable_ForceFallsThrough verifies that
// when force=true, ready_gate=true, and the server is not reachable, the
// shim falls through to bash.real instead of failing. This is the boot-time safety fix.
func TestShimReadinessGate_ServerUnreachable_ForceFallsThrough(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-shim tests require Unix")
	}

	tmp := t.TempDir()
	shimBin := buildShim(t, tmp)
	if err := os.Symlink("/bin/sh", filepath.Join(tmp, "sh.real")); err != nil {
		t.Fatal(err)
	}

	confDir := filepath.Join(tmp, "etc", "agentsh")
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(confDir, "shim.conf"), []byte("force=true\nready_gate=true\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Point AGENTSH_SERVER at a port where nothing is listening.
	// The readiness gate should fail, causing fallthrough to sh.real.
	cmd := exec.Command(shimBin, "-c", "echo readiness-fallthrough")
	cmd.Stdin = strings.NewReader("") // non-TTY
	cmd.Env = []string{
		"PATH=/usr/bin:/bin",
		"AGENTSH_SESSION_ID=test-session",
		"AGENTSH_SHIM_CONF_ROOT=" + tmp,
		"AGENTSH_SERVER=http://127.0.0.1:1", // nothing listens on port 1
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	// Should succeed: fell through to sh.real which ran "echo readiness-fallthrough".
	if err != nil {
		t.Fatalf("expected success (fallthrough to sh.real), got error: %v\nstderr: %s", err, stderr.String())
	}
	if got := strings.TrimSpace(stdout.String()); got != "readiness-fallthrough" {
		t.Fatalf("stdout = %q, want %q", got, "readiness-fallthrough")
	}
}

// TestShimReadinessGate_NoReadyGate_FailsClosed verifies that without
// ready_gate=true, the shim does NOT fall through when the local server
// is unreachable — it tries to enforce and fails (fail-closed default).
func TestShimReadinessGate_NoReadyGate_FailsClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-shim tests require Unix")
	}

	tmp := t.TempDir()
	shimBin := buildShim(t, tmp)
	if err := os.Symlink("/bin/sh", filepath.Join(tmp, "sh.real")); err != nil {
		t.Fatal(err)
	}

	confDir := filepath.Join(tmp, "etc", "agentsh")
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// force=true but NO ready_gate — should fail-closed.
	if err := os.WriteFile(filepath.Join(confDir, "shim.conf"), []byte("force=true\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(shimBin, "-c", "echo should-not-run")
	cmd.Stdin = strings.NewReader("") // non-TTY
	cmd.Env = []string{
		"PATH=/usr/bin:/bin",
		"AGENTSH_SESSION_ID=test-session",
		"AGENTSH_SHIM_CONF_ROOT=" + tmp,
		"AGENTSH_SERVER=http://127.0.0.1:1", // unreachable
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	// Should FAIL: no ready_gate, so shim tries to enforce (find agentsh) and fails.
	if err == nil {
		t.Fatalf("expected error: without ready_gate, shim should try to enforce and fail")
	}
	if !strings.Contains(stderr.String(), "agentsh") {
		t.Fatalf("expected agentsh-related error, got stderr: %s", stderr.String())
	}
}

// TestShimReadinessGate_ServerReachable_ForceEnforces verifies that when
// force=true, ready_gate=true, and the server IS reachable, the shim
// proceeds to enforcement (gate passes, enforcement kicks in).
func TestShimReadinessGate_ServerReachable_ForceEnforces(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-shim tests require Unix")
	}

	tmp := t.TempDir()
	shimBin := buildShim(t, tmp)
	if err := os.Symlink("/bin/sh", filepath.Join(tmp, "sh.real")); err != nil {
		t.Fatal(err)
	}

	confDir := filepath.Join(tmp, "etc", "agentsh")
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(confDir, "shim.conf"), []byte("force=true\nready_gate=true\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Start a real TCP listener so the readiness gate passes.
	srvURL := startFakeServer(t)

	cmd := exec.Command(shimBin, "-c", "echo hello")
	cmd.Stdin = strings.NewReader("") // non-TTY
	cmd.Env = []string{
		"PATH=/usr/bin:/bin",
		"AGENTSH_SESSION_ID=test-session",
		"AGENTSH_SHIM_CONF_ROOT=" + tmp,
		"AGENTSH_SERVER=" + srvURL,
		// No AGENTSH_BIN — agentsh not available, so enforce will fail.
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	// Should FAIL: readiness gate passed, shim tried to enforce, couldn't find agentsh.
	if err == nil {
		t.Fatalf("expected error: server reachable, shim should enforce and fail (no agentsh)")
	}
	if !strings.Contains(stderr.String(), "agentsh") {
		t.Fatalf("expected agentsh-related error, got stderr: %s", stderr.String())
	}
}

// TestShimReadinessGate_ServerUnreachable_NonInteractiveBypass verifies that
// the non-interactive bypass still works when the server is unreachable
// and force is not set (default path — no regression).
func TestShimReadinessGate_ServerUnreachable_NonInteractiveBypass(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-shim tests require Unix")
	}

	tmp := t.TempDir()
	shimBin := buildShim(t, tmp)
	if err := os.Symlink("/bin/sh", filepath.Join(tmp, "sh.real")); err != nil {
		t.Fatal(err)
	}

	// No shim.conf, no AGENTSH_SHIM_FORCE — default non-interactive bypass.
	cmd := exec.Command(shimBin, "-c", "echo non-interactive-ok")
	cmd.Stdin = strings.NewReader("") // non-TTY
	cmd.Env = []string{
		"PATH=/usr/bin:/bin",
		"AGENTSH_SESSION_ID=test-session",
		"AGENTSH_SERVER=http://127.0.0.1:1", // unreachable
	}

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	err := cmd.Run()
	if err != nil {
		t.Fatalf("expected success (non-interactive bypass), got error: %v", err)
	}
	if got := strings.TrimSpace(stdout.String()); got != "non-interactive-ok" {
		t.Fatalf("stdout = %q, want %q", got, "non-interactive-ok")
	}
}

// TestShimReadinessGate_RemoteUnreachable_FailsClosed verifies that when the
// server is remote (non-loopback) and unreachable, the shim fails closed
// even with ready_gate=true. Only local servers get fail-open behavior.
func TestShimReadinessGate_RemoteUnreachable_FailsClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-shim tests require Unix")
	}

	tmp := t.TempDir()
	shimBin := buildShim(t, tmp)
	if err := os.Symlink("/bin/sh", filepath.Join(tmp, "sh.real")); err != nil {
		t.Fatal(err)
	}

	confDir := filepath.Join(tmp, "etc", "agentsh")
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(confDir, "shim.conf"), []byte("force=true\nready_gate=true\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Point at a remote (non-loopback) address that won't respond.
	// Use a non-routable IP so dial fails quickly (ENETUNREACH or timeout).
	cmd := exec.Command(shimBin, "-c", "echo should-not-run")
	cmd.Stdin = strings.NewReader("") // non-TTY
	cmd.Env = []string{
		"PATH=/usr/bin:/bin",
		"AGENTSH_SESSION_ID=test-session",
		"AGENTSH_SHIM_CONF_ROOT=" + tmp,
		"AGENTSH_SERVER=http://192.0.2.1:18080", // TEST-NET-1: non-routable
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	// Should FAIL (fail-closed for remote servers).
	if err == nil {
		t.Fatalf("expected error: remote unreachable should fail-closed, not fall through")
	}
	if !strings.Contains(stderr.String(), "remote server not reachable") {
		t.Fatalf("expected remote-specific error, got stderr: %s", stderr.String())
	}
}

func TestServerAddrFromEnv(t *testing.T) {
	tests := []struct {
		name        string
		env         string
		wantNetwork string
		wantAddr    string
		wantErr     bool
	}{
		{"empty", "", "tcp", "127.0.0.1:18080", false},
		{"default URL", "http://127.0.0.1:18080", "tcp", "127.0.0.1:18080", false},
		{"custom port", "http://127.0.0.1:9999", "tcp", "127.0.0.1:9999", false},
		{"localhost", "http://localhost:18080", "tcp", "localhost:18080", false},
		{"remote host", "http://10.0.0.5:18080", "tcp", "10.0.0.5:18080", false},
		{"https with port", "https://agent.example.com:443", "tcp", "agent.example.com:443", false},
		{"https no port", "https://agent.example.com", "tcp", "agent.example.com:443", false},
		{"http no port", "http://127.0.0.1", "tcp", "127.0.0.1:80", false},
		{"garbage", "://bad", "", "", true},
		{"unix socket", "unix:///var/run/agentsh.sock", "unix", "/var/run/agentsh.sock", false},
		{"unix socket no triple slash", "unix:/var/run/agentsh.sock", "unix", "/var/run/agentsh.sock", false},
		{"unix socket host+path", "unix://host/path/to/sock", "unix", "host/path/to/sock", false},
		// Schemeless values that url.Parse accepts as path-only — must be rejected.
		{"schemeless hostname", "localhost", "", "", true},
		{"schemeless path", "/tmp/agentsh.sock", "", "", true},
		// Empty host with path — must be rejected.
		{"http empty host", "http:///bad", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("AGENTSH_SERVER", tt.env)
			gotNet, gotAddr, gotErr := serverAddrFromEnv()
			if (gotErr != nil) != tt.wantErr {
				t.Errorf("serverAddrFromEnv() error = %v, wantErr %v", gotErr, tt.wantErr)
				return
			}
			if gotErr != nil {
				return
			}
			if gotNet != tt.wantNetwork || gotAddr != tt.wantAddr {
				t.Errorf("serverAddrFromEnv() = (%q, %q), want (%q, %q)", gotNet, gotAddr, tt.wantNetwork, tt.wantAddr)
			}
		})
	}
}

func TestServerIsLocal(t *testing.T) {
	tests := []struct {
		name    string
		network string
		addr    string
		want    bool
	}{
		{"loopback", "tcp", "127.0.0.1:18080", true},
		{"localhost", "tcp", "localhost:18080", true},
		{"loopback ipv6", "tcp", "[::1]:18080", true},
		{"remote ip", "tcp", "10.0.0.5:18080", false},
		{"remote hostname", "tcp", "agent.example.com:443", false},
		{"unix socket", "unix", "/var/run/agentsh.sock", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := serverIsLocal(tt.network, tt.addr)
			if got != tt.want {
				t.Errorf("serverIsLocal(%q, %q) = %v, want %v", tt.network, tt.addr, got, tt.want)
			}
		})
	}
}

func TestIsAgentshCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-shim tests require Unix")
	}

	// Create a fake agentsh binary in a temp dir.
	tmp := t.TempDir()
	agentshBin := filepath.Join(tmp, "agentsh")
	if err := os.WriteFile(agentshBin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENTSH_BIN", agentshBin)
	t.Setenv("PATH", tmp+":"+os.Getenv("PATH"))

	tests := []struct {
		name string
		args []string
		want bool
	}{
		{"agentsh detect", []string{"-c", "agentsh detect"}, true},
		{"agentsh --version", []string{"-c", "agentsh --version"}, true},
		{"agentsh trash list", []string{"-c", "agentsh trash list"}, true},
		{"absolute path", []string{"-c", agentshBin + " detect"}, true},
		{"exec agentsh", []string{"-c", "exec agentsh detect"}, true},
		{"nice agentsh", []string{"-c", "nice agentsh detect"}, true},
		{"command agentsh", []string{"-c", "command agentsh detect"}, true},
		// -lc and -l -c are intentionally NOT handled (login shell PATH risk).
		{"-lc flag", []string{"-lc", "agentsh detect"}, false},
		{"-l -c split", []string{"-l", "-c", "agentsh detect"}, false},
		{"echo hello", []string{"-c", "echo hello"}, false},
		{"sudo agentsh", []string{"-c", "sudo agentsh detect"}, false},
		// env and VAR=VAL prefixes are NOT skipped (they can modify PATH).
		{"env agentsh", []string{"-c", "env agentsh detect"}, false},
		{"env VAR=1 agentsh", []string{"-c", "env FOO=bar agentsh detect"}, false},
		{"env -i agentsh", []string{"-c", "env -i agentsh detect"}, false},
		{"bare VAR=VAL prefix", []string{"-c", "FOO=1 agentsh detect"}, false},
		{"PATH override", []string{"-c", "PATH=/tmp agentsh detect"}, false},
		// -c must be the first argument (not further into args).
		{"--norc -c", []string{"--norc", "-c", "agentsh detect"}, false},
		// Login shell flags — bypass disabled.
		{"-l -c login", []string{"-l", "-c", "agentsh detect"}, false},
		{"--login -c", []string{"--login", "-c", "agentsh detect"}, false},
		// Compound commands — bypass disabled (could bypass enforcement for chained commands).
		{"semicolon chain", []string{"-c", "agentsh detect; echo done"}, false},
		{"and chain", []string{"-c", "agentsh detect && echo done"}, false},
		{"or chain", []string{"-c", "agentsh detect || echo done"}, false},
		{"pipe", []string{"-c", "agentsh detect | grep ok"}, false},
		{"subshell", []string{"-c", "$(agentsh detect)"}, false},
		{"backtick", []string{"-c", "`agentsh detect`"}, false},
		{"newline separator", []string{"-c", "agentsh detect\nother-cmd"}, false},
		// Redirections are NOT compound — they're single commands.
		{"stderr redirect", []string{"-c", "agentsh detect 2>&1"}, true},
		{"stdout redirect", []string{"-c", "agentsh detect > /dev/null"}, true},
		{"stderr to file", []string{"-c", "agentsh detect 2>/dev/null"}, true},
		{"script with -c arg", []string{"script.sh", "-c", "agentsh detect"}, false},
		{"no -c flag", []string{"agentsh", "detect"}, false},
		{"empty command", []string{"-c", ""}, false},
		{"just -c", []string{"-c"}, false},
		{"no args", []string{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isAgentshCommand(tt.args)
			if got != tt.want {
				t.Errorf("isAgentshCommand(%v) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}

func TestIsAgentshCommand_Symlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-shim tests require Unix")
	}

	tmp := t.TempDir()
	// Real binary in a subdirectory.
	realDir := filepath.Join(tmp, "real")
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	realBin := filepath.Join(realDir, "agentsh")
	if err := os.WriteFile(realBin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Symlink in PATH.
	binDir := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realBin, filepath.Join(binDir, "agentsh")); err != nil {
		t.Fatal(err)
	}

	// AGENTSH_BIN points to real binary, PATH has symlink.
	t.Setenv("AGENTSH_BIN", realBin)
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	// Should detect agentsh even though PATH resolves to a symlink.
	if !isAgentshCommand([]string{"-c", "agentsh detect"}) {
		t.Fatalf("expected true: symlinked agentsh should be detected")
	}
}

// TestShimConfValidationError_FailsWithMessage verifies that a typo in
// shim.conf (e.g. ready_gate=tru) fails with a clear error message instead
// of being silently swallowed into the fail-closed force=true path. Without
// this, a typo disabling the readiness gate would leave operators in the
// exact boot-loop the gate is meant to prevent.
func TestShimConfValidationError_FailsWithMessage(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-shim tests require Unix")
	}

	tmp := t.TempDir()
	shimBin := buildShim(t, tmp)
	if err := os.Symlink("/bin/sh", filepath.Join(tmp, "sh.real")); err != nil {
		t.Fatal(err)
	}

	confDir := filepath.Join(tmp, "etc", "agentsh")
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Typo: "tru" instead of "true".
	if err := os.WriteFile(filepath.Join(confDir, "shim.conf"), []byte("ready_gate=tru\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(shimBin, "-c", "echo should-not-run")
	cmd.Stdin = strings.NewReader("") // non-TTY
	cmd.Env = []string{
		"PATH=/usr/bin:/bin",
		"AGENTSH_SESSION_ID=test-session",
		"AGENTSH_SHIM_CONF_ROOT=" + tmp,
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err == nil {
		t.Fatalf("expected error for typo in shim.conf, but shim succeeded")
	}
	// Must mention the invalid value, not just "agentsh" resolve errors.
	if !strings.Contains(stderr.String(), "invalid ready_gate") {
		t.Fatalf("expected validation error message, got stderr: %s", stderr.String())
	}
}

func TestFatalWithHint(t *testing.T) {
	// Verify formatting and exit code by forking a subprocess.
	if os.Getenv("AGENTSH_SHIM_FATAL_TEST") == "1" {
		fatalWithHint(5, "msg", "hint")
		return
	}

	t.Run("writes message and exits with code", func(t *testing.T) {
		cmd := exec.Command(os.Args[0], "-test.run", t.Name())
		cmd.Env = append(os.Environ(), "AGENTSH_SHIM_FATAL_TEST=1")
		out, err := cmd.CombinedOutput()
		var ee *exec.ExitError
		if err == nil || !errors.As(err, &ee) || ee.ExitCode() != 5 {
			t.Fatalf("expected exit code 5, got err=%v output=%s", err, out)
		}
		if !strings.Contains(string(out), "msg") || !strings.Contains(string(out), "Hint: hint") {
			t.Fatalf("unexpected output: %s", out)
		}
	})
}

// TestShimForced_StdinMode_CapturesOutput verifies the Daytona stdin-mode fix:
// Daytona invokes bare /bin/bash (no args) and sends commands via stdin.
// The shim must detect this, read stdin, convert to -c, and route through
// agentsh exec for policy enforcement. Output must be captured.
func TestShimForced_StdinMode_CapturesOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-shim tests require Unix")
	}

	tmp := t.TempDir()
	shimBin := buildShim(t, tmp)
	if err := os.Symlink("/bin/sh", filepath.Join(tmp, "sh.real")); err != nil {
		t.Fatal(err)
	}

	fakeAgentsh := filepath.Join(tmp, "agentsh")
	fakeScript := `#!/bin/sh
# Simulate agentsh exec: skip flags until --, then exec the command
while [ "$1" != "--" ] && [ $# -gt 0 ]; do shift; done
shift  # skip the --
exec "$@"
`
	if err := os.WriteFile(fakeAgentsh, []byte(fakeScript), 0o755); err != nil {
		t.Fatal(err)
	}

	// Simulate Daytona: invoke bare /bin/bash (no args), send command on stdin.
	cmd := exec.Command(shimBin) // no -c, no args — bare invocation
	cmd.Stdin = strings.NewReader("echo stdin-mode-works\n")
	cmd.Env = []string{
		"PATH=" + tmp + ":/usr/bin:/bin",
		"AGENTSH_SESSION_ID=test-session",
		"AGENTSH_SHIM_FORCE=1",
		"AGENTSH_BIN=" + fakeAgentsh,
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("shim exited with error: %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
	}

	gotOut := strings.TrimSpace(stdout.String())
	if gotOut != "stdin-mode-works" {
		t.Errorf("stdout = %q, want %q (stdin-mode: command from stdin not executed)", gotOut, "stdin-mode-works")
	}
}

// TestShimForced_StdinMode_MultiLine verifies that multi-line stdin commands
// are correctly converted to -c and executed.
func TestShimForced_StdinMode_MultiLine(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-shim tests require Unix")
	}

	tmp := t.TempDir()
	shimBin := buildShim(t, tmp)
	if err := os.Symlink("/bin/sh", filepath.Join(tmp, "sh.real")); err != nil {
		t.Fatal(err)
	}

	fakeAgentsh := filepath.Join(tmp, "agentsh")
	fakeScript := `#!/bin/sh
while [ "$1" != "--" ] && [ $# -gt 0 ]; do shift; done
shift
exec "$@"
`
	if err := os.WriteFile(fakeAgentsh, []byte(fakeScript), 0o755); err != nil {
		t.Fatal(err)
	}

	// Multi-line script on stdin.
	cmd := exec.Command(shimBin)
	cmd.Stdin = strings.NewReader("echo line1\necho line2\n")
	cmd.Env = []string{
		"PATH=" + tmp + ":/usr/bin:/bin",
		"AGENTSH_SESSION_ID=test-session",
		"AGENTSH_SHIM_FORCE=1",
		"AGENTSH_BIN=" + fakeAgentsh,
	}

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		t.Fatalf("shim exited with error: %v", err)
	}

	got := stdout.String()
	if !strings.Contains(got, "line1") || !strings.Contains(got, "line2") {
		t.Errorf("stdout = %q, want both line1 and line2", got)
	}
}

// TestShimForced_StdinMode_PropagatesExitCode verifies exit code propagation
// when using stdin-mode.
func TestShimForced_StdinMode_PropagatesExitCode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-shim tests require Unix")
	}

	tmp := t.TempDir()
	shimBin := buildShim(t, tmp)
	if err := os.Symlink("/bin/sh", filepath.Join(tmp, "sh.real")); err != nil {
		t.Fatal(err)
	}

	fakeAgentsh := filepath.Join(tmp, "agentsh")
	fakeScript := `#!/bin/sh
while [ "$1" != "--" ] && [ $# -gt 0 ]; do shift; done
shift
exec "$@"
`
	if err := os.WriteFile(fakeAgentsh, []byte(fakeScript), 0o755); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(shimBin)
	cmd.Stdin = strings.NewReader("exit 77\n")
	cmd.Env = []string{
		"PATH=" + tmp + ":/usr/bin:/bin",
		"AGENTSH_SESSION_ID=test-session",
		"AGENTSH_SHIM_FORCE=1",
		"AGENTSH_BIN=" + fakeAgentsh,
	}

	err := cmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit code")
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("expected ExitError, got %T: %v", err, err)
	}
	if ee.ExitCode() != 77 {
		t.Fatalf("exit code = %d, want 77", ee.ExitCode())
	}
}

// TestShimForced_NonPTY_CapturesOutput verifies the fix for Bug 3:
// in forced non-PTY mode (Daytona pattern), the shim must capture all output
// from the agentsh exec child process. With syscall.Exec, the output was lost
// because the toolbox didn't see data written by the exec'd process. With
// exec.Command (the fix), the shim stays alive as a parent, piping output through.
//
// This simulates the Daytona toolbox pattern: start the shim with pipes for
// stdout/stderr, force non-interactive enforcement, and verify output arrives.
func TestShimForced_NonPTY_CapturesOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-shim tests require Unix")
	}

	tmp := t.TempDir()
	shimBin := buildShim(t, tmp)
	if err := os.Symlink("/bin/sh", filepath.Join(tmp, "sh.real")); err != nil {
		t.Fatal(err)
	}

	// Create a fake agentsh binary that simulates "agentsh exec":
	// skip args until "--", then run the remaining args as a command.
	// This mimics the real CLI connecting to the server and printing output.
	fakeAgentsh := filepath.Join(tmp, "agentsh")
	fakeScript := `#!/bin/sh
# Simulate agentsh exec: skip flags until --, then exec the command
while [ "$1" != "--" ] && [ $# -gt 0 ]; do shift; done
shift  # skip the --
exec "$@"
`
	if err := os.WriteFile(fakeAgentsh, []byte(fakeScript), 0o755); err != nil {
		t.Fatal(err)
	}

	// Run the shim in forced non-PTY mode (simulating Daytona).
	// Stdin is a pipe (non-TTY), AGENTSH_SHIM_FORCE=1 prevents bypass.
	cmd := exec.Command(shimBin, "-c", "echo daytona-capture-test && echo stderr-test >&2")
	cmd.Stdin = strings.NewReader("") // non-TTY
	cmd.Env = []string{
		"PATH=" + tmp + ":/usr/bin:/bin",
		"AGENTSH_SESSION_ID=test-session",
		"AGENTSH_SHIM_FORCE=1",
		"AGENTSH_BIN=" + fakeAgentsh,
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("shim exited with error: %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
	}

	// Verify stdout was captured (this is what failed with syscall.Exec in Daytona).
	gotOut := strings.TrimSpace(stdout.String())
	if gotOut != "daytona-capture-test" {
		t.Errorf("stdout = %q, want %q (Bug 3: output not captured in non-PTY forced mode)", gotOut, "daytona-capture-test")
	}

	// Verify stderr was also captured.
	if !strings.Contains(stderr.String(), "stderr-test") {
		t.Errorf("stderr missing expected content; got: %q", stderr.String())
	}
}

// TestShimForced_NonPTY_PropagatesExitCode verifies that in forced non-PTY mode,
// the shim correctly propagates the child's exit code.
func TestShimForced_NonPTY_PropagatesExitCode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-shim tests require Unix")
	}

	tmp := t.TempDir()
	shimBin := buildShim(t, tmp)
	if err := os.Symlink("/bin/sh", filepath.Join(tmp, "sh.real")); err != nil {
		t.Fatal(err)
	}

	fakeAgentsh := filepath.Join(tmp, "agentsh")
	fakeScript := `#!/bin/sh
while [ "$1" != "--" ] && [ $# -gt 0 ]; do shift; done
shift
exec "$@"
`
	if err := os.WriteFile(fakeAgentsh, []byte(fakeScript), 0o755); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(shimBin, "-c", "exit 42")
	cmd.Stdin = strings.NewReader("")
	cmd.Env = []string{
		"PATH=" + tmp + ":/usr/bin:/bin",
		"AGENTSH_SESSION_ID=test-session",
		"AGENTSH_SHIM_FORCE=1",
		"AGENTSH_BIN=" + fakeAgentsh,
	}

	err := cmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit code")
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("expected ExitError, got %T: %v", err, err)
	}
	if ee.ExitCode() != 42 {
		t.Fatalf("exit code = %d, want 42", ee.ExitCode())
	}
}
