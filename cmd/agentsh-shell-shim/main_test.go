package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveAgentshBin(t *testing.T) {
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
