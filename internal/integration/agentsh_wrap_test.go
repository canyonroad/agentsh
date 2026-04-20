//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/pkg/types"
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

const wrapStrongTestConfigYAML = `
server:
  http:
    addr: "0.0.0.0:18080"
auth:
  type: "api_key"
  api_key:
    keys_file: "/keys.yaml"
    header_name: "X-API-Key"
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
    enabled: true
    wrapper_bin: "/usr/local/bin/agentsh-unixwrap"
  seccomp:
    unix_socket:
      enabled: true
    execve:
      enabled: true
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

func TestWrapFallback_OmitsInSessionMarker(t *testing.T) {
	ctx := context.Background()

	bin := buildAgentshBinary(t)
	temp := t.TempDir()

	configPath := filepath.Join(temp, "config.yaml")
	writeFile(t, configPath, wrapTestConfigYAML)

	policiesDir := filepath.Join(temp, "policies")
	mustMkdir(t, policiesDir)
	writeFile(t, filepath.Join(policiesDir, "agent-default.yaml"), wrapTestPolicyYAML)

	workspace := filepath.Join(temp, "workspace")
	mustMkdir(t, workspace)

	req := testcontainers.ContainerRequest{
		Image: "debian:bookworm-slim",
		Cmd: []string{
			"/usr/local/bin/agentsh", "wrap", "--", "/usr/bin/env",
		},
		Mounts: []testcontainers.ContainerMount{
			testcontainers.BindMount(bin, "/usr/local/bin/agentsh"),
			testcontainers.BindMount(configPath, "/config.yaml"),
			testcontainers.BindMount(policiesDir, "/policies"),
			testcontainers.BindMount(workspace, "/workspace"),
		},
		Env: map[string]string{"AGENTSH_CONFIG": "/config.yaml"},
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.SecurityOpt = []string{"apparmor:unconfined", "seccomp:unconfined"}
		},
		WaitingFor: wait.ForExit().WithExitTimeout(30 * time.Second),
	}

	ctr, err := startContainerWithRetry(t, ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("start container: %v", err)
	}
	defer func() { _ = ctr.Terminate(context.Background()) }()

	logs, err := ctr.Logs(ctx)
	if err != nil {
		t.Fatalf("get logs: %v", err)
	}
	defer logs.Close()

	logBytes, err := io.ReadAll(logs)
	if err != nil {
		t.Fatalf("read logs: %v", err)
	}
	logOutput := string(logBytes)

	if strings.Contains(logOutput, "AGENTSH_IN_SESSION=1") {
		t.Fatalf("did not expect AGENTSH_IN_SESSION=1 in fallback wrap output, got:\n%s", logOutput)
	}
}

func TestWrapStrongMode_SetsInSessionMarker(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	agentshBin, unixwrapBin := buildSeccompBinaries(t)
	temp := t.TempDir()

	configPath := filepath.Join(temp, "config.yaml")
	writeFile(t, configPath, wrapStrongTestConfigYAML)
	keysPath := filepath.Join(temp, "keys.yaml")
	writeFile(t, keysPath, testAPIKeysYAML)

	policiesDir := filepath.Join(temp, "policies")
	mustMkdir(t, policiesDir)
	writeFile(t, filepath.Join(policiesDir, "agent-default.yaml"), wrapTestPolicyYAML)

	workspace := filepath.Join(temp, "workspace")
	mustMkdir(t, workspace)

	ctr, endpoint, cleanup := startWrapSeccompServerContainer(t, ctx, agentshBin, unixwrapBin, configPath, keysPath, policiesDir, workspace)
	t.Cleanup(cleanup)

	cli := client.New(endpoint, "test-key")

	probeSess, err := cli.CreateSession(ctx, "/workspace", "agent-default")
	if err != nil {
		t.Fatalf("CreateSession probe: %v", err)
	}
	t.Cleanup(func() {
		if err := cli.DestroySession(context.Background(), probeSess.ID); err != nil {
			t.Logf("DestroySession probe: %v", err)
		}
	})

	probeCtx, probeCancel := context.WithTimeout(ctx, 10*time.Second)
	probeResult, probeErr := cli.Exec(probeCtx, probeSess.ID, types.ExecRequest{
		Command: "/bin/echo",
		Args:    []string{"probe"},
	})
	probeCancel()

	if probeErr != nil {
		if errors.Is(probeErr, context.DeadlineExceeded) || strings.Contains(probeErr.Error(), "deadline exceeded") {
			t.Skip("seccomp-user-notify appears unreliable in this environment (probe timeout)")
		}
		t.Fatalf("Exec probe: %v", probeErr)
	}
	if probeResult.Result.ExitCode != 0 {
		t.Skip("seccomp-user-notify may not be active in this environment (probe exit non-zero)")
	}

	exitCode, outputReader, err := ctr.Exec(ctx, []string{
		"/bin/sh", "-lc",
		`timeout 20s env AGENTSH_NO_AUTO=1 AGENTSH_API_KEY=test-key /usr/local/bin/agentsh --server http://127.0.0.1:18080 wrap -- /usr/bin/env 2>&1`,
	})
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "deadline exceeded") {
			t.Skip("seccomp wrap execution appears unreliable in this environment (wrap timeout)")
		}
		t.Fatalf("wrap exec: %v", err)
	}
	logBytes, err := io.ReadAll(outputReader)
	if err != nil {
		t.Fatalf("read wrap exec output: %v", err)
	}
	logOutput := string(logBytes)

	if exitCode == 124 {
		t.Skipf("seccomp wrap execution appears unreliable in this environment (wrap timed out)\n%s", logOutput)
	}
	if exitCode != 0 {
		t.Fatalf("wrap exec exit=%d output:\n%s", exitCode, logOutput)
	}
	if !strings.Contains(logOutput, "AGENTSH_IN_SESSION=1") {
		t.Fatalf("expected AGENTSH_IN_SESSION=1 in strong wrap output, got:\n%s", logOutput)
	}
}

func startWrapSeccompServerContainer(
	t *testing.T,
	ctx context.Context,
	agentshBin string,
	unixwrapBin string,
	configPath string,
	keysPath string,
	policiesDir string,
	workspace string,
) (testcontainers.Container, string, func()) {
	t.Helper()

	req := testcontainers.ContainerRequest{
		Image:        "debian:bookworm-slim",
		ExposedPorts: []string{"18080/tcp"},
		Cmd:          []string{"/usr/local/bin/agentsh", "server", "--config", "/config.yaml"},
		Mounts: []testcontainers.ContainerMount{
			testcontainers.BindMount(agentshBin, "/usr/local/bin/agentsh"),
			testcontainers.BindMount(unixwrapBin, "/usr/local/bin/agentsh-unixwrap"),
			testcontainers.BindMount(configPath, "/config.yaml"),
			testcontainers.BindMount(keysPath, "/keys.yaml"),
			testcontainers.BindMount(policiesDir, "/policies"),
			testcontainers.BindMount(workspace, "/workspace"),
		},
		Privileged: true,
		CapAdd:     []string{"SYS_ADMIN"},
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.SecurityOpt = []string{"apparmor:unconfined", "seccomp:unconfined"}
		},
		WaitingFor: wait.ForHTTP("/health").
			WithPort("18080/tcp").
			WithStartupTimeout(60 * time.Second).
			WithStatusCodeMatcher(func(code int) bool { return code >= 200 && code < 500 }),
	}

	ctr, err := startContainerWithRetry(t, ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("start seccomp server container: %v", err)
	}

	host, err := ctr.Host(ctx)
	if err != nil {
		t.Fatalf("container host: %v", err)
	}
	mappedPort, err := ctr.MappedPort(ctx, "18080/tcp")
	if err != nil {
		t.Fatalf("map port: %v", err)
	}
	endpoint := fmt.Sprintf("http://%s:%s", host, mappedPort.Port())

	cleanup := func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cleanupCancel()
		if logs, err := ctr.Logs(cleanupCtx); err == nil {
			defer logs.Close()
			b, _ := io.ReadAll(logs)
			if len(b) > 0 {
				t.Logf("container logs:\n%s", string(b))
			}
		}
		_ = ctr.Terminate(cleanupCtx)
	}

	return ctr, endpoint, cleanup
}
