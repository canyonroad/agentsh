//go:build integration

package integration

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const wrapTestConfigYAML = `
server:
  http:
    addr: "127.0.0.1:18080"
auth:
  type: "none"
logging:
  level: "info"
  format: "text"
  output: "stdout"
audit:
  enabled: false
  storage:
    sqlite_path: "/tmp/events.db"
sessions:
  base_dir: "/sessions"
sandbox:
  fuse:
    enabled: false
  network:
    enabled: false
  unix_sockets:
    enabled: false
  seccomp:
    execve:
      enabled: false
policies:
  dir: "/policies"
  default: "agent-default"
approvals:
  enabled: false
metrics:
  enabled: false
health:
  path: "/health"
`

const wrapTestPolicyYAML = `
version: 1
name: agent-default
description: permissive policy for wrap integration test
command_rules:
  - name: allow-all
    commands: ["*"]
    decision: allow
resource_limits:
  command_timeout: 30s
  session_timeout: 1h
  idle_timeout: 30m
`

func TestWrapAutoStart(t *testing.T) {
	ctx := context.Background()

	// Build the agentsh binary (CGO_ENABLED=0, same as policy tests).
	// Without CGO, seccomp is unavailable — wrap falls back to direct launch.
	// This test targets autostart + session + child execution, not seccomp.
	bin := buildAgentshBinary(t)

	temp := t.TempDir()

	// Write config and policy files
	configPath := filepath.Join(temp, "config.yaml")
	writeFile(t, configPath, wrapTestConfigYAML)

	policiesDir := filepath.Join(temp, "policies")
	mustMkdir(t, policiesDir)
	writeFile(t, filepath.Join(policiesDir, "agent-default.yaml"), wrapTestPolicyYAML)

	workspace := filepath.Join(temp, "workspace")
	mustMkdir(t, workspace)

	binds := []testcontainers.ContainerMount{
		testcontainers.BindMount(bin, "/usr/local/bin/agentsh"),
		testcontainers.BindMount(configPath, "/config.yaml"),
		testcontainers.BindMount(policiesDir, "/policies"),
		testcontainers.BindMount(workspace, "/workspace"),
	}

	// Run "agentsh wrap -- echo hello" with no pre-started server.
	// The wrap command should autostart the server, create a session,
	// run "echo hello", and exit cleanly.
	req := testcontainers.ContainerRequest{
		Image:  "debian:bookworm-slim",
		Cmd:    []string{"/usr/local/bin/agentsh", "wrap", "--", "echo", "hello"},
		Mounts: binds,
		Env:    map[string]string{"AGENTSH_CONFIG": "/config.yaml"},
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.SecurityOpt = []string{"apparmor:unconfined", "seccomp:unconfined"}
		},
		WaitingFor: wait.ForExit().WithExitTimeout(30 * time.Second),
	}

	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		if ctr != nil {
			if logs, logErr := ctr.Logs(ctx); logErr == nil {
				defer logs.Close()
				b, _ := io.ReadAll(logs)
				t.Logf("container logs:\n%s", string(b))
			}
		}
		t.Fatalf("start container: %v", err)
	}
	defer func() { _ = ctr.Terminate(context.Background()) }()

	// Read container logs for assertions
	logs, err := ctr.Logs(ctx)
	if err != nil {
		t.Fatalf("get container logs: %v", err)
	}
	defer logs.Close()
	logBytes, err := io.ReadAll(logs)
	if err != nil {
		t.Fatalf("read container logs: %v", err)
	}
	logOutput := string(logBytes)
	t.Logf("container logs:\n%s", logOutput)

	// Check exit code
	state, err := ctr.State(ctx)
	if err != nil {
		t.Fatalf("get container state: %v", err)
	}
	if state.ExitCode != 0 {
		t.Fatalf("container exited with code %d, expected 0", state.ExitCode)
	}

	// Verify autostart fired
	if !strings.Contains(logOutput, "auto-starting server") {
		t.Error("expected log line containing 'auto-starting server' (autostart should have fired)")
	}

	// Verify session was created
	if !strings.Contains(logOutput, "session") || !strings.Contains(logOutput, "created") {
		t.Error("expected log output containing 'session' and 'created' (session should have been established)")
	}

	// Verify the child command produced output
	if !strings.Contains(logOutput, "hello") {
		t.Error("expected 'hello' in output (echo command should have run)")
	}
}
