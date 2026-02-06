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
