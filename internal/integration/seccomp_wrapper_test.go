//go:build integration

package integration

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/docker/docker/api/types/container"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TestSeccompWrapperEnabled verifies that when unix_sockets.enabled=true,
// the server starts successfully, can create sessions, and exec commands work.
// The wrapper may fail to set up seccomp in the container environment (due to
// seccomp:unconfined), but the server should gracefully handle this with a timeout
// and still complete the exec.
func TestSeccompWrapperEnabled(t *testing.T) {
	ctx := context.Background()

	// Build binaries with CGO for seccomp support
	agentshBin, unixwrapBin := buildSeccompBinaries(t)

	temp := t.TempDir()

	policiesDir := filepath.Join(temp, "policies")
	mustMkdir(t, policiesDir)
	writeFile(t, filepath.Join(policiesDir, "default.yaml"), seccompTestPolicyYAML)

	keysPath := filepath.Join(temp, "keys.yaml")
	writeFile(t, keysPath, testAPIKeysYAML)

	configPath := filepath.Join(temp, "config.yaml")
	writeFile(t, configPath, seccompTestConfigYAML)

	workspace := filepath.Join(temp, "workspace")
	mustMkdir(t, workspace)

	endpoint, cleanup := startSeccompServerContainer(t, ctx, agentshBin, unixwrapBin, configPath, policiesDir, workspace)
	t.Cleanup(cleanup)

	cli := client.New(endpoint, "test-key")

	// Verify session creation works with wrapper config enabled
	sess, err := cli.CreateSession(ctx, "/workspace", "default")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	t.Logf("Session created: %s", sess.ID)

	// Test exec with wrapper enabled - the wrapper may not be able to set up
	// seccomp in a container with seccomp:unconfined, but the timeout should
	// prevent blocking and the command should still execute.
	execCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	execReq := types.ExecRequest{
		Command:    "/bin/echo",
		Args:       []string{"hello", "from", "wrapper"},
		WorkingDir: "/workspace",
	}
	result, err := cli.Exec(execCtx, sess.ID, execReq)
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	t.Logf("Exec result: exit=%d, stdout=%q", result.Result.ExitCode, result.Result.Stdout)

	if result.Result.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", result.Result.ExitCode)
	}
	expectedOutput := "hello from wrapper\n"
	if result.Result.Stdout != expectedOutput {
		t.Errorf("expected stdout %q, got %q", expectedOutput, result.Result.Stdout)
	}

	if err := cli.DestroySession(ctx, sess.ID); err != nil {
		t.Fatalf("DestroySession: %v", err)
	}
}

// TestSeccompWrapperDisabled verifies that the server starts when unix_sockets is disabled.
func TestSeccompWrapperDisabled(t *testing.T) {
	ctx := context.Background()

	// Build binaries - CGO not strictly required when disabled, but use same binaries
	agentshBin, unixwrapBin := buildSeccompBinaries(t)

	temp := t.TempDir()

	policiesDir := filepath.Join(temp, "policies")
	mustMkdir(t, policiesDir)
	writeFile(t, filepath.Join(policiesDir, "default.yaml"), seccompTestPolicyYAML)

	keysPath := filepath.Join(temp, "keys.yaml")
	writeFile(t, keysPath, testAPIKeysYAML)

	configPath := filepath.Join(temp, "config.yaml")
	writeFile(t, configPath, seccompDisabledConfigYAML)

	workspace := filepath.Join(temp, "workspace")
	mustMkdir(t, workspace)

	endpoint, cleanup := startSeccompServerContainer(t, ctx, agentshBin, unixwrapBin, configPath, policiesDir, workspace)
	t.Cleanup(cleanup)

	cli := client.New(endpoint, "test-key")

	// Verify session creation works with wrapper disabled
	sess, err := cli.CreateSession(ctx, "/workspace", "default")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	t.Logf("Session created: %s", sess.ID)

	if err := cli.DestroySession(ctx, sess.ID); err != nil {
		t.Fatalf("DestroySession: %v", err)
	}
}

func buildSeccompBinaries(t *testing.T) (agentsh, unixwrap string) {
	t.Helper()

	tempDir := t.TempDir()
	agentshOut := filepath.Join(tempDir, "agentsh")
	unixwrapOut := filepath.Join(tempDir, "agentsh-unixwrap")

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	repoRoot := wd
	for {
		if _, err := os.Stat(filepath.Join(repoRoot, "go.mod")); err == nil {
			break
		}
		next := filepath.Dir(repoRoot)
		if next == repoRoot {
			t.Fatalf("go.mod not found when walking up from %s", wd)
		}
		repoRoot = next
	}

	// Build agentsh with CGO enabled for full seccomp support
	cmd := exec.Command("go", "build", "-o", agentshOut, "./cmd/agentsh")
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=1")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("go build agentsh: %v", err)
	}

	// Build agentsh-unixwrap with CGO (required for seccomp)
	cmd = exec.Command("go", "build", "-o", unixwrapOut, "./cmd/agentsh-unixwrap")
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=1")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("go build agentsh-unixwrap: %v", err)
	}

	return agentshOut, unixwrapOut
}

func startSeccompServerContainer(t *testing.T, ctx context.Context, agentshBin, unixwrapBin, configPath, policiesDir, workspace string) (string, func()) {
	t.Helper()

	binds := []testcontainers.ContainerMount{
		testcontainers.BindMount(agentshBin, "/usr/local/bin/agentsh"),
		testcontainers.BindMount(unixwrapBin, "/usr/local/bin/agentsh-unixwrap"),
		testcontainers.BindMount(configPath, "/config.yaml"),
		testcontainers.BindMount(filepath.Join(filepath.Dir(configPath), "keys.yaml"), "/keys.yaml"),
		testcontainers.BindMount(policiesDir, "/policies"),
		testcontainers.BindMount(workspace, "/workspace"),
	}

	req := testcontainers.ContainerRequest{
		Image:        "debian:bookworm-slim",
		ExposedPorts: []string{"8080/tcp"},
		Cmd:          []string{"/usr/local/bin/agentsh", "server", "--config", "/config.yaml"},
		Mounts:       binds,
		Privileged:   true,
		CapAdd:       []string{"SYS_ADMIN"},
		HostConfigModifier: func(hc *container.HostConfig) {
			// Need seccomp:unconfined to allow the wrapper to install its own seccomp filters
			hc.SecurityOpt = []string{"apparmor:unconfined", "seccomp:unconfined"}
		},
		WaitingFor: wait.ForHTTP("/health").
			WithPort("8080/tcp").
			WithStartupTimeout(60 * time.Second).
			WithStatusCodeMatcher(func(code int) bool { return code == http.StatusOK || code == http.StatusNotFound }),
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

	host, err := ctr.Host(ctx)
	if err != nil {
		t.Fatalf("container host: %v", err)
	}
	mappedPort, err := ctr.MappedPort(ctx, "8080/tcp")
	if err != nil {
		t.Fatalf("map port: %v", err)
	}
	endpoint := fmt.Sprintf("http://%s:%s", host, mappedPort.Port())

	cleanup := func() {
		// Log container output for debugging
		if logs, err := ctr.Logs(context.Background()); err == nil {
			defer logs.Close()
			b, _ := io.ReadAll(logs)
			if len(b) > 0 {
				t.Logf("container logs:\n%s", string(b))
			}
		}
		_ = ctr.Terminate(context.Background())
	}
	return endpoint, cleanup
}

const seccompTestPolicyYAML = `
version: 1
name: default
description: seccomp integration test policy
command_rules:
  - name: allow-all
    commands: []
    decision: allow
file_rules:
  - name: allow-all
    paths: ["/**"]
    operations: [read, write, delete]
    decision: allow
resource_limits:
  command_timeout: 30s
  session_timeout: 1h
  idle_timeout: 30m
`

const seccompTestConfigYAML = `
server:
  http:
    addr: "0.0.0.0:8080"
auth:
  type: "api_key"
  api_key:
    keys_file: "/keys.yaml"
    header_name: "X-API-Key"
logging:
  level: "debug"
  format: "text"
  output: "stdout"
audit:
  enabled: false
  storage:
    sqlite_path: "/tmp/events.db"
sessions:
  base_dir: "/tmp/sessions"
  retention:
    enabled: false
sandbox:
  fuse:
    enabled: false
  network:
    enabled: false
  unix_sockets:
    enabled: true
policies:
  dir: "/policies"
  default: "default"
approvals:
  enabled: false
metrics:
  enabled: false
health:
  path: "/health"
trash:
  enabled: false
`

const seccompDisabledConfigYAML = `
server:
  http:
    addr: "0.0.0.0:8080"
auth:
  type: "api_key"
  api_key:
    keys_file: "/keys.yaml"
    header_name: "X-API-Key"
logging:
  level: "debug"
  format: "text"
  output: "stdout"
audit:
  enabled: false
  storage:
    sqlite_path: "/tmp/events.db"
sessions:
  base_dir: "/tmp/sessions"
  retention:
    enabled: false
sandbox:
  fuse:
    enabled: false
  network:
    enabled: false
  unix_sockets:
    enabled: false
policies:
  dir: "/policies"
  default: "default"
approvals:
  enabled: false
metrics:
  enabled: false
health:
  path: "/health"
trash:
  enabled: false
`
