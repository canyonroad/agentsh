package shim_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestShellShim_UsesAgentshBinAndForwardsArgs(t *testing.T) {
	repoRoot := repoRootOrSkip(t)
	tmp := t.TempDir()

	shimBin := filepath.Join(tmp, "agentsh-shell-shim")
	buildOrSkip(t, repoRoot, "./cmd/agentsh-shell-shim", shimBin)

	binDir := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	shimPath := filepath.Join(binDir, "sh")
	copyFile(t, shimBin, shimPath, 0o755)

	realPath := filepath.Join(binDir, "sh.real")
	if err := os.WriteFile(realPath, []byte("#!/bin/sh\necho REAL_SH\n"), 0o755); err != nil {
		t.Fatalf("write sh.real: %v", err)
	}

	fakeAgentsh := filepath.Join(tmp, "fake-agentsh")
	logPath := filepath.Join(tmp, "agentsh.log")
	writeFakeAgentsh(t, fakeAgentsh, logPath)

	cmd := exec.Command(shimPath, "-lc", "echo hi")
	cmd.Env = append(os.Environ(),
		"AGENTSH_BIN="+fakeAgentsh,
		"AGENTSH_SESSION_ID=session-test",
		"AGENTSH_SERVER=http://127.0.0.1:1",
		"FAKE_AGENTSH_LOG="+logPath,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("shim failed: %v (out=%s)", err, string(out))
	}

	lines := mustReadLines(t, logPath)
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "ARG0=exec") {
		t.Fatalf("expected exec subcommand in %q", joined)
	}
	if !strings.Contains(joined, "ARG1=--argv0") {
		t.Fatalf("expected --argv0 in %q", joined)
	}
	if !strings.Contains(joined, "ARG2="+shimPath) {
		t.Fatalf("expected argv0 to match shim path; got %q", joined)
	}
	if !strings.Contains(joined, "ARG3=session-test") {
		t.Fatalf("expected session id; got %q", joined)
	}
	if !strings.Contains(joined, "ARG4=--") {
		t.Fatalf("expected -- separator; got %q", joined)
	}
	if !strings.Contains(joined, "ARG5="+realPath) {
		t.Fatalf("expected real shell path; got %q", joined)
	}
	if strings.Contains(joined, "--pty") {
		t.Fatalf("did not expect --pty when not a TTY; got %q", joined)
	}
}

func TestShellShim_UsesPATHWhenAgentshBinUnset(t *testing.T) {
	repoRoot := repoRootOrSkip(t)
	tmp := t.TempDir()

	shimBin := filepath.Join(tmp, "agentsh-shell-shim")
	buildOrSkip(t, repoRoot, "./cmd/agentsh-shell-shim", shimBin)

	binDir := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	shimPath := filepath.Join(binDir, "sh")
	copyFile(t, shimBin, shimPath, 0o755)
	if err := os.WriteFile(filepath.Join(binDir, "sh.real"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write sh.real: %v", err)
	}

	fakeDir := filepath.Join(tmp, "fakebin")
	if err := os.MkdirAll(fakeDir, 0o755); err != nil {
		t.Fatalf("mkdir fakebin: %v", err)
	}
	logPath := filepath.Join(tmp, "agentsh.log")
	writeFakeAgentsh(t, filepath.Join(fakeDir, "agentsh"), logPath)

	cmd := exec.Command(shimPath, "-lc", "echo hi")
	cmd.Env = append(os.Environ(),
		"PATH="+fakeDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"AGENTSH_SESSION_ID=session-test",
		"FAKE_AGENTSH_LOG="+logPath,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("shim failed: %v (out=%s)", err, string(out))
	}

	lines := mustReadLines(t, logPath)
	if len(lines) == 0 || !strings.HasPrefix(lines[0], "ARG0=exec") {
		t.Fatalf("expected fake agentsh to run; got %v", lines)
	}
}

func TestShellShim_RecursionGuardExecsRealShell(t *testing.T) {
	repoRoot := repoRootOrSkip(t)
	tmp := t.TempDir()

	shimBin := filepath.Join(tmp, "agentsh-shell-shim")
	buildOrSkip(t, repoRoot, "./cmd/agentsh-shell-shim", shimBin)

	binDir := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	shimPath := filepath.Join(binDir, "sh")
	copyFile(t, shimBin, shimPath, 0o755)

	realPath := filepath.Join(binDir, "sh.real")
	if err := os.WriteFile(realPath, []byte("#!/bin/sh\necho RECURSION_OK\n"), 0o755); err != nil {
		t.Fatalf("write sh.real: %v", err)
	}

	cmd := exec.Command(shimPath, "-lc", "echo hi")
	cmd.Env = append(os.Environ(),
		"AGENTSH_IN_SESSION=1",
		"AGENTSH_BIN=/nonexistent/agentsh",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("shim failed: %v (out=%s)", err, string(out))
	}
	if !strings.Contains(string(out), "RECURSION_OK") {
		t.Fatalf("expected real shell to run, got %q", string(out))
	}
}

func TestShellShim_RespectsCustomArgv0(t *testing.T) {
	repoRoot := repoRootOrSkip(t)
	tmp := t.TempDir()

	shimBin := filepath.Join(tmp, "agentsh-shell-shim")
	buildOrSkip(t, repoRoot, "./cmd/agentsh-shell-shim", shimBin)

	binDir := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	shimPath := filepath.Join(binDir, "sh")
	copyFile(t, shimBin, shimPath, 0o755)
	realPath := filepath.Join(binDir, "sh.real")
	if err := os.WriteFile(realPath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write sh.real: %v", err)
	}

	fakeAgentsh := filepath.Join(tmp, "fake-agentsh")
	logPath := filepath.Join(tmp, "agentsh.log")
	writeFakeAgentsh(t, fakeAgentsh, logPath)

	cmd := exec.Command(shimPath, "-lc", "echo hi")
	// Override argv0 to simulate a harness exec'ing /bin/sh but pointing to our shim.
	cmd.Args[0] = "/bin/sh"
	cmd.Env = append(os.Environ(),
		"AGENTSH_BIN="+fakeAgentsh,
		"AGENTSH_SESSION_ID=session-test",
		"FAKE_AGENTSH_LOG="+logPath,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("shim failed: %v (out=%s)", err, string(out))
	}

	lines := mustReadLines(t, logPath)
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "ARG2=/bin/sh") {
		t.Fatalf("expected argv0=/bin/sh to be forwarded; got %q", joined)
	}
}

func TestShellShim_LoginArgv0SelectsBash(t *testing.T) {
	repoRoot := repoRootOrSkip(t)
	tmp := t.TempDir()

	shimBin := filepath.Join(tmp, "agentsh-shell-shim")
	buildOrSkip(t, repoRoot, "./cmd/agentsh-shell-shim", shimBin)

	binDir := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Install shim at "bash" and provide bash.real next to it so resolveRealShell can find it.
	shimPath := filepath.Join(binDir, "bash")
	copyFile(t, shimBin, shimPath, 0o755)
	realPath := filepath.Join(binDir, "bash.real")
	if err := os.WriteFile(realPath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write bash.real: %v", err)
	}

	fakeAgentsh := filepath.Join(tmp, "fake-agentsh")
	logPath := filepath.Join(tmp, "agentsh.log")
	writeFakeAgentsh(t, fakeAgentsh, logPath)

	cmd := exec.Command(shimPath, "-lc", "echo hi")
	// Simulate login shell argv0 ("-bash").
	cmd.Args[0] = "-bash"
	cmd.Env = append(os.Environ(),
		"AGENTSH_BIN="+fakeAgentsh,
		"AGENTSH_SESSION_ID=session-test",
		"FAKE_AGENTSH_LOG="+logPath,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("shim failed: %v (out=%s)", err, string(out))
	}

	lines := mustReadLines(t, logPath)
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "ARG2=-bash") {
		t.Fatalf("expected argv0=-bash to be forwarded; got %q", joined)
	}
	if !strings.Contains(joined, "ARG5="+realPath) {
		t.Fatalf("expected real shell bash.real; got %q", joined)
	}
}

func repoRootOrSkip(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Skipf("getwd: %v", err)
	}
	dir := wd
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Skip("repo root not found (go.mod)")
	return ""
}

func buildOrSkip(t *testing.T, repoRoot, pkg, out string) {
	t.Helper()
	cmd := exec.Command("go", "build", "-o", out, pkg)
	cmd.Dir = repoRoot
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("go build failed: %v (out=%s)", err, string(b))
	}
}

func copyFile(t *testing.T, src, dst string, mode os.FileMode) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read %s: %v", src, err)
	}
	if err := os.WriteFile(dst, b, mode); err != nil {
		t.Fatalf("write %s: %v", dst, err)
	}
}

func writeFakeAgentsh(t *testing.T, path, logPath string) {
	t.Helper()
	s := `#!/bin/sh
set -eu
log="${FAKE_AGENTSH_LOG:-` + logPath + `}"
rm -f "$log"
i=0
for a in "$@"; do
  echo "ARG${i}=${a}" >>"$log"
  i=$((i+1))
done
exit 0
`
	if err := os.WriteFile(path, []byte(s), 0o755); err != nil {
		t.Fatalf("write fake agentsh: %v", err)
	}
}

func mustReadLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}
