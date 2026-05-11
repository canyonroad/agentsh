package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestProbeShimTier_DetectsShimOnPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-based probe is POSIX only")
	}
	dir := t.TempDir()
	shimDir := filepath.Join(dir, "shims")
	if err := os.Mkdir(shimDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Place a fake `curl` executable in the shim dir.
	fakeCurl := filepath.Join(shimDir, "curl")
	if err := os.WriteFile(fakeCurl, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Inject the shim dir at the front of PATH for the probe.
	t.Setenv("PATH", shimDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	ok, resolved, err := probeShimTier(shimDir)
	if err != nil {
		t.Fatalf("probeShimTier: %v", err)
	}
	if !ok {
		t.Errorf("expected probe to detect shim; resolved=%q", resolved)
	}
	if !strings.HasPrefix(resolved, shimDir) {
		t.Errorf("resolved %q should be under shim dir %q", resolved, shimDir)
	}
}

func TestProbeShimTier_RejectsRealCurl(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-based probe is POSIX only")
	}
	// Don't put any shim on PATH. The system curl (if present) should NOT
	// match the shim dir, so the probe returns false.
	t.Setenv("PATH", "/usr/bin:/bin")
	ok, _, err := probeShimTier("/nonexistent/shims")
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != 1 {
			t.Fatalf("unexpected probe error: %v", err)
		}
		// exit 1 = "curl not found"; acceptable on hosts without curl
	}
	if ok {
		t.Errorf("expected probe to NOT detect shim when only /usr/bin/curl is reachable")
	}
}

func TestWriteTierFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tier")
	if err := writeTierFile(path, "shim"); err != nil {
		t.Fatalf("writeTierFile: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "shim\n" {
		t.Errorf("tier file = %q, want %q", got, "shim\n")
	}
}
