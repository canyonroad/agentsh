package main

import (
	"bytes"
	"errors"
	"io"
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

	// No AGENTSH_SHIM_FORCE env var — config file alone should trigger enforce.
	// The shim will try to find agentsh and fail, proving it didn't bypass.
	cmd := exec.Command(shimBin, "-c", "echo hello")
	cmd.Stdin = strings.NewReader("") // non-TTY
	cmd.Env = []string{
		"PATH=/usr/bin:/bin",
		"AGENTSH_SESSION_ID=test-session",
		"AGENTSH_SHIM_CONF_ROOT=" + tmp,
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

	cmd := exec.Command(shimBin, "-c", "echo hello")
	cmd.Stdin = strings.NewReader("") // non-TTY
	cmd.Env = []string{
		"PATH=/usr/bin:/bin",
		"AGENTSH_SESSION_ID=test-session",
		"AGENTSH_SHIM_CONF_ROOT=" + tmp,
		"AGENTSH_SHIM_FORCE=0",
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

	cmd := exec.Command(shimBin, "-c", "echo hello")
	cmd.Stdin = strings.NewReader("") // non-TTY
	cmd.Env = []string{
		"PATH=/usr/bin:/bin",
		"AGENTSH_SESSION_ID=test-session",
		"AGENTSH_SHIM_CONF_ROOT=" + tmp,
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
		{"pipe", []string{"-c", "agentsh detect | grep ok"}, false},
		{"subshell", []string{"-c", "$(agentsh detect)"}, false},
		{"backtick", []string{"-c", "`agentsh detect`"}, false},
		{"newline separator", []string{"-c", "agentsh detect\nother-cmd"}, false},
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
