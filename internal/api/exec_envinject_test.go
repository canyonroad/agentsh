package api

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
)

// TestRunCommand_EnvInjectStdoutCapture verifies that stdout is captured correctly
// when extraProcConfig has envInject values (the v0.16.8 earlyReturn path).
// This is the exact path taken in Daytona sandboxes where:
//   - ptrace: disabled (tracer=nil)
//   - cgroups: disabled (hook=nil)
//   - unix_sockets: disabled (no wrapper)
//   - env_inject has BASH_ENV and AGENTSH_SERVER
func TestRunCommand_EnvInjectStdoutCapture(t *testing.T) {
	ws := t.TempDir()
	s := &session.Session{
		ID:        "session-envinject",
		Workspace: ws,
		Cwd:       "/workspace",
		Env:       map[string]string{},
	}
	s.SetWorkspaceMount(ws)

	cfg := &config.Config{}

	tests := []struct {
		name  string
		extra *extraProcConfig
	}{
		{
			name:  "nil extra (v0.16.5 behavior)",
			extra: nil,
		},
		{
			name: "envInject with two keys (v0.16.8 earlyReturn path)",
			extra: &extraProcConfig{
				envInject: map[string]string{
					"BASH_ENV":       "/nonexistent/bash_startup.sh",
					"AGENTSH_SERVER": "http://localhost:9999",
				},
			},
		},
		{
			name: "envInject with one key that overrides existing",
			extra: &extraProcConfig{
				envInject: map[string]string{
					"HOME": "/tmp/override",
				},
			},
		},
		{
			name: "envInject with empty map",
			extra: &extraProcConfig{
				envInject: map[string]string{},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := types.ExecRequest{Command: "sh", Args: []string{"-c", "echo hello-envinject"}}

			exitCode, stdout, stderr, stdoutTotal, _, _, _, _, err := runCommandWithResources(
				context.Background(), s, "cmd-envinject", req, cfg,
				policy.ResolvedEnvPolicy{}, 0, nil, tc.extra, nil, "")

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if exitCode != 0 {
				t.Fatalf("expected exit code 0, got %d; stderr: %s", exitCode, string(stderr))
			}
			got := strings.TrimSpace(string(stdout))
			if got != "hello-envinject" {
				t.Errorf("stdout = %q (total=%d), want %q; stderr: %s", got, stdoutTotal, "hello-envinject", string(stderr))
			}
		})
	}
}

// TestRunCommand_EnvInjectPreservesEnv verifies the environment slice is correctly
// constructed when envInject filtering runs (the in-place filter at exec.go:199).
func TestRunCommand_EnvInjectPreservesEnv(t *testing.T) {
	ws := t.TempDir()
	s := &session.Session{
		ID:        "session-envcheck",
		Workspace: ws,
		Cwd:       "/workspace",
		Env:       map[string]string{},
	}
	s.SetWorkspaceMount(ws)

	cfg := &config.Config{}
	extra := &extraProcConfig{
		envInject: map[string]string{
			"MY_INJECT_VAR": "injected_value",
		},
	}

	// Run a command that prints the injected var AND PATH (to verify env isn't corrupted)
	req := types.ExecRequest{
		Command: "sh",
		Args:    []string{"-c", "echo inject=$MY_INJECT_VAR path_set=$( [ -n \"$PATH\" ] && echo yes || echo no )"},
	}

	exitCode, stdout, stderr, _, _, _, _, _, err := runCommandWithResources(
		context.Background(), s, "cmd-envcheck", req, cfg,
		policy.ResolvedEnvPolicy{}, 0, nil, extra, nil, "")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("exit code %d; stderr: %s", exitCode, string(stderr))
	}

	out := strings.TrimSpace(string(stdout))
	if !strings.Contains(out, "inject=injected_value") {
		t.Errorf("envInject value not visible in child env; stdout: %q", out)
	}
	if !strings.Contains(out, "path_set=yes") {
		t.Errorf("PATH missing from child env (env corruption?); stdout: %q", out)
	}
}

// TestRunCommand_EnvInjectWithBASH_ENV verifies stdout capture when BASH_ENV
// is injected and points to a script with the Bug 1 issue (enable ordering).
func TestRunCommand_EnvInjectWithBASH_ENV(t *testing.T) {
	ws := t.TempDir()
	s := &session.Session{
		ID:        "session-bashenv",
		Workspace: ws,
		Cwd:       "/workspace",
		Env:       map[string]string{},
	}
	s.SetWorkspaceMount(ws)

	// Create a BASH_ENV script with the Bug 1 issue
	bashEnvPath := filepath.Join(ws, "bash_startup_buggy.sh")
	if err := os.WriteFile(bashEnvPath, []byte(`#!/bin/bash
enable -n kill
enable -n enable
enable -n ulimit
enable -n umask
enable -n builtin
enable -n command
`), 0o755); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	extra := &extraProcConfig{
		envInject: map[string]string{
			"BASH_ENV": bashEnvPath,
		},
	}

	// Use bash (not sh) since BASH_ENV is bash-specific
	bashPath := "/bin/bash"
	if _, err := os.Stat(bashPath); err != nil {
		bashPath = "/usr/bin/bash"
		if _, err := os.Stat(bashPath); err != nil {
			t.Skip("bash not found")
		}
	}

	req := types.ExecRequest{Command: bashPath, Args: []string{"-c", "echo bash-env-test"}}

	exitCode, stdout, stderr, stdoutTotal, _, _, _, _, err := runCommandWithResources(
		context.Background(), s, "cmd-bashenv", req, cfg,
		policy.ResolvedEnvPolicy{}, 0, nil, extra, nil, "")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	t.Logf("exit=%d stdout=%q (total=%d) stderr=%q", exitCode, string(stdout), stdoutTotal, string(stderr))

	got := strings.TrimSpace(string(stdout))
	if got != "bash-env-test" {
		t.Errorf("stdout = %q, want %q (BASH_ENV may be interfering with stdout capture)", got, "bash-env-test")
	}
}
