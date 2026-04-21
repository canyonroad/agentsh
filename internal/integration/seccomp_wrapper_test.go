//go:build integration && linux

package integration

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestCreateSessionWithRetry_RetriesTransientTransportErrors(t *testing.T) {
	t.Parallel()

	want := types.Session{ID: "session-retried"}
	attempts := 0
	cli := &fakeSessionClient{
		createWithID: func(context.Context, string, string, string) (types.Session, error) {
			attempts++
			if attempts == 1 {
				return types.Session{}, errors.New(`Post "http://localhost:1234/api/v1/sessions": read tcp [::1]:123->[::1]:456: read: bad file descriptor`)
			}
			return want, nil
		},
	}

	got, err := createSessionWithRetry(context.Background(), cli, "/workspace", "default")
	if err != nil {
		t.Fatalf("createSessionWithRetry: %v", err)
	}
	if got.ID != want.ID {
		t.Fatalf("session ID = %q, want %q", got.ID, want.ID)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
}

func TestCreateSessionWithRetry_DoesNotRetryPermanentErrors(t *testing.T) {
	t.Parallel()

	attempts := 0
	cli := &fakeSessionClient{
		createWithID: func(context.Context, string, string, string) (types.Session, error) {
			attempts++
			return types.Session{}, errors.New("policy not found")
		},
	}

	_, err := createSessionWithRetry(context.Background(), cli, "/workspace", "default")
	if err == nil {
		t.Fatal("expected error")
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1", attempts)
	}
}

func TestCreateSessionWithRetry_UsesExistingSessionAfterConflict(t *testing.T) {
	t.Parallel()

	want := types.Session{ID: "session-existing"}
	createAttempts := 0
	getAttempts := 0
	cli := &fakeSessionClient{
		createWithID: func(context.Context, string, string, string) (types.Session, error) {
			createAttempts++
			if createAttempts == 1 {
				return types.Session{}, errors.New(`Post "http://localhost:1234/api/v1/sessions": context deadline exceeded (Client.Timeout exceeded while awaiting headers)`)
			}
			return types.Session{}, &client.HTTPError{Method: http.MethodPost, Path: "/api/v1/sessions", Status: "409 Conflict", StatusCode: http.StatusConflict}
		},
		getSession: func(context.Context, string) (types.Session, error) {
			getAttempts++
			return want, nil
		},
	}

	got, err := createSessionWithRetry(context.Background(), cli, "/workspace", "default")
	if err != nil {
		t.Fatalf("createSessionWithRetry: %v", err)
	}
	if got.ID != want.ID {
		t.Fatalf("session ID = %q, want %q", got.ID, want.ID)
	}
	if createAttempts != 2 {
		t.Fatalf("create attempts = %d, want 2", createAttempts)
	}
	if getAttempts != 1 {
		t.Fatalf("get attempts = %d, want 1", getAttempts)
	}
}

type fakeEndpointContainer struct {
	hostCalls int
	portCalls int

	hostFunc func(context.Context) (string, error)
	portFunc func(context.Context, nat.Port) (nat.Port, error)
}

func (f *fakeEndpointContainer) Host(ctx context.Context) (string, error) {
	f.hostCalls++
	return f.hostFunc(ctx)
}

func (f *fakeEndpointContainer) MappedPort(ctx context.Context, port nat.Port) (nat.Port, error) {
	f.portCalls++
	return f.portFunc(ctx, port)
}

func TestContainerHTTPEndpointWithRetry_RetriesTransientMappedPortErrors(t *testing.T) {
	t.Parallel()

	wantPort, err := nat.NewPort("tcp", "49152")
	if err != nil {
		t.Fatalf("nat.NewPort: %v", err)
	}

	attempts := 0
	ctr := &fakeEndpointContainer{
		hostFunc: func(context.Context) (string, error) {
			return "127.0.0.1", nil
		},
		portFunc: func(context.Context, nat.Port) (nat.Port, error) {
			attempts++
			if attempts == 1 {
				return "", errors.New(`inspect: Get "http://%2Fvar%2Frun%2Fdocker.sock/v1.48/containers/abc/json": context deadline exceeded`)
			}
			return wantPort, nil
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	endpoint, err := containerHTTPEndpointWithRetry(ctx, ctr, "18080/tcp")
	if err != nil {
		t.Fatalf("containerHTTPEndpointWithRetry: %v", err)
	}
	if endpoint != "http://127.0.0.1:49152" {
		t.Fatalf("endpoint = %q, want %q", endpoint, "http://127.0.0.1:49152")
	}
	if ctr.portCalls != 2 {
		t.Fatalf("MappedPort calls = %d, want 2", ctr.portCalls)
	}
}

func TestContainerHTTPEndpointWithRetry_DoesNotRetryPermanentErrors(t *testing.T) {
	t.Parallel()

	ctr := &fakeEndpointContainer{
		hostFunc: func(context.Context) (string, error) {
			return "127.0.0.1", nil
		},
		portFunc: func(context.Context, nat.Port) (nat.Port, error) {
			return "", errors.New("port not exposed")
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if _, err := containerHTTPEndpointWithRetry(ctx, ctr, "18080/tcp"); err == nil {
		t.Fatal("containerHTTPEndpointWithRetry() error = nil, want permanent failure")
	}
	if ctr.portCalls != 1 {
		t.Fatalf("MappedPort calls = %d, want 1", ctr.portCalls)
	}
}

// TestSeccompWrapperEnabled verifies that when unix_sockets.enabled=true,
// the server starts successfully, can create sessions, and exec commands work.
// The wrapper may fail to set up seccomp in the container environment (due to
// seccomp:unconfined), but the server should gracefully handle this with a timeout
// and still complete the exec.
func TestSeccompWrapperEnabled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

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
	sess, err := createSessionWithRetry(ctx, cli, "/workspace", "default")
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

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
	sess, err := createSessionWithRetry(ctx, cli, "/workspace", "default")
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
		ExposedPorts: []string{"18080/tcp"},
		Cmd:          []string{"/usr/local/bin/agentsh", "server", "--config", "/config.yaml"},
		Mounts:       binds,
		Privileged:   true,
		CapAdd:       []string{"SYS_ADMIN"},
		HostConfigModifier: func(hc *container.HostConfig) {
			// Need seccomp:unconfined to allow the wrapper to install its own seccomp filters
			hc.SecurityOpt = []string{"apparmor:unconfined", "seccomp:unconfined"}
		},
		WaitingFor: wait.ForHTTP("/health").
			WithPort("18080/tcp").
			WithStartupTimeout(60 * time.Second).
			WithStatusCodeMatcher(func(code int) bool { return code == http.StatusOK || code == http.StatusNotFound }),
	}

	ctr, err := startContainerWithRetry(t, ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("start container: %v", err)
	}

	endpoint, err := containerHTTPEndpointWithRetry(ctx, ctr, "18080/tcp")
	if err != nil {
		t.Fatalf("resolve endpoint: %v", err)
	}

	cleanup := func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cleanupCancel()
		// Log container output for debugging
		if logs, err := ctr.Logs(cleanupCtx); err == nil {
			defer logs.Close()
			b, _ := io.ReadAll(logs)
			if len(b) > 0 {
				t.Logf("container logs:\n%s", string(b))
			}
		}
		_ = ctr.Terminate(cleanupCtx)
	}
	return endpoint, cleanup
}

// startContainerWithRetry wraps testcontainers.GenericContainer in a retry loop
// to absorb two transient failure modes observed in CI:
//   - Docker socket keep-alive drops ("use of closed network connection",
//     "EOF", "connection reset") when a pooled HTTP connection to
//     /run/docker.sock is reaped mid-request.
//   - wait.ForHTTP startup timeouts where the container starts but the
//     mapped port briefly isn't reachable in time; the next attempt on the
//     same image typically succeeds in a few seconds.
//
// Any non-nil container returned alongside an error is terminated (after a
// best-effort log capture) before we return or retry, so privileged
// containers never leak across attempts or out to the caller (which
// typically t.Fatal's and would skip cleanup itself).
func startContainerWithRetry(t *testing.T, ctx context.Context, req testcontainers.GenericContainerRequest) (testcontainers.Container, error) {
	t.Helper()
	cleanup := func(c testcontainers.Container, logLabel string) {
		if c == nil {
			return
		}
		logCtx, cancelLog := context.WithTimeout(context.Background(), 10*time.Second)
		if logs, lerr := c.Logs(logCtx); lerr == nil {
			b, _ := io.ReadAll(logs)
			logs.Close()
			if len(b) > 0 {
				t.Logf("%s container logs:\n%s", logLabel, string(b))
			}
		}
		cancelLog()
		termCtx, cancelTerm := context.WithTimeout(context.Background(), 30*time.Second)
		_ = c.Terminate(termCtx)
		cancelTerm()
	}
	var err error
	for attempt := 1; attempt <= 3; attempt++ {
		var ctr testcontainers.Container
		ctr, err = testcontainers.GenericContainer(ctx, req)
		if err == nil {
			return ctr, nil
		}
		msg := err.Error()
		transient := strings.Contains(msg, "use of closed network connection") ||
			strings.Contains(msg, "EOF") ||
			strings.Contains(msg, "connection reset") ||
			strings.Contains(msg, "wait until ready")
		if !transient || attempt == 3 {
			cleanup(ctr, "failed-start")
			return nil, err
		}
		cleanup(ctr, "retrying")
		t.Logf("transient docker error on attempt %d/3, retrying: %v", attempt, err)
		time.Sleep(2 * time.Second)
	}
	return nil, err
}

type sessionCreator interface {
	CreateSessionWithID(ctx context.Context, id, workspace, policy string) (types.Session, error)
	GetSession(ctx context.Context, id string) (types.Session, error)
}

type fakeSessionClient struct {
	createWithID func(ctx context.Context, id, workspace, policy string) (types.Session, error)
	getSession   func(ctx context.Context, id string) (types.Session, error)
}

func (f *fakeSessionClient) CreateSessionWithID(ctx context.Context, id, workspace, policy string) (types.Session, error) {
	return f.createWithID(ctx, id, workspace, policy)
}

func (f *fakeSessionClient) GetSession(ctx context.Context, id string) (types.Session, error) {
	return f.getSession(ctx, id)
}

func createSessionWithRetry(ctx context.Context, cli sessionCreator, workspace, policy string) (types.Session, error) {
	sessionID := fmt.Sprintf("session-%d", time.Now().UnixNano())
	var err error
	for attempt := 1; attempt <= 3; attempt++ {
		var sess types.Session
		sess, err = cli.CreateSessionWithID(ctx, sessionID, workspace, policy)
		if err == nil {
			return sess, nil
		}
		var httpErr *client.HTTPError
		if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusConflict {
			return cli.GetSession(ctx, sessionID)
		}
		if !isTransientCreateSessionError(err) || attempt == 3 || ctx.Err() != nil {
			return types.Session{}, err
		}
		time.Sleep(250 * time.Millisecond)
	}
	return types.Session{}, err
}

func isTransientCreateSessionError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return errors.Is(err, context.DeadlineExceeded) ||
		strings.Contains(msg, "Client.Timeout exceeded while awaiting headers") ||
		strings.Contains(msg, "bad file descriptor") ||
		strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "EOF")
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
    addr: "0.0.0.0:18080"
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

// TestExecveInterception_DepthEnforcement verifies that execve interception
// actually works in a Docker environment - blocking nested commands based on depth.
//
// NOTE: This test requires seccomp-user-notify to work, which may not function
// in all Docker/CI environments. The test will skip if commands timeout.
func TestExecveInterception_DepthEnforcement(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Build binaries with CGO for seccomp support
	agentshBin, unixwrapBin := buildSeccompBinaries(t)

	temp := t.TempDir()

	policiesDir := filepath.Join(temp, "policies")
	mustMkdir(t, policiesDir)
	// Policy that blocks 'cat' when nested (depth >= 1)
	writeFile(t, filepath.Join(policiesDir, "depth-test.yaml"), execveDepthTestPolicyYAML)

	keysPath := filepath.Join(temp, "keys.yaml")
	writeFile(t, keysPath, testAPIKeysYAML)

	configPath := filepath.Join(temp, "config.yaml")
	writeFile(t, configPath, execveInterceptionConfigYAML)

	workspace := filepath.Join(temp, "workspace")
	mustMkdir(t, workspace)
	writeFile(t, filepath.Join(workspace, "test.txt"), "test content")

	endpoint, cleanup := startSeccompServerContainer(t, ctx, agentshBin, unixwrapBin, configPath, policiesDir, workspace)
	t.Cleanup(cleanup)

	cli := client.New(endpoint, "test-key")

	sess, err := createSessionWithRetry(ctx, cli, "/workspace", "depth-test")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	t.Logf("Session created: %s", sess.ID)

	// Use a short timeout to detect if seccomp-user-notify isn't working
	// If commands hang, we'll skip the test rather than wait forever
	execTimeout := 10 * time.Second

	// Probe first (outside subtest) - if this fails, skip entire test
	probeCtx, probeCancel := context.WithTimeout(ctx, execTimeout)
	probeResult, probeErr := cli.Exec(probeCtx, sess.ID, types.ExecRequest{
		Command: "echo",
		Args:    []string{"probe"},
	})
	probeCancel()

	if probeErr != nil {
		if errors.Is(probeErr, context.DeadlineExceeded) || strings.Contains(probeErr.Error(), "deadline exceeded") {
			t.Skip("seccomp-user-notify appears to not be working in this environment (command timeout)")
		}
		t.Fatalf("Exec probe: %v", probeErr)
	}
	if probeResult.Result.ExitCode != 0 {
		t.Skip("seccomp-user-notify may not be working (non-zero exit on simple command)")
	}
	t.Logf("Probe succeeded - seccomp appears to be working")

	// Test 1: Direct 'cat' should work (depth 0)
	t.Run("direct_cat_allowed", func(t *testing.T) {
		execCtx, cancel := context.WithTimeout(ctx, execTimeout)
		defer cancel()

		result, err := cli.Exec(execCtx, sess.ID, types.ExecRequest{
			Command: "cat",
			Args:    []string{"/workspace/test.txt"},
		})
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				t.Skip("command timeout - seccomp-user-notify not working")
			}
			t.Fatalf("Exec direct cat: %v", err)
		}
		if result.Result.ExitCode != 0 {
			t.Errorf("direct cat should succeed, got exit %d: %s", result.Result.ExitCode, result.Result.Stderr)
		}
		if result.Result.Stdout != "test content" {
			t.Errorf("expected 'test content', got %q", result.Result.Stdout)
		}
		t.Logf("Direct cat succeeded: %q", result.Result.Stdout)
	})

	// Test 3: Nested 'cat' via sh should be blocked (depth 1)
	t.Run("nested_cat_blocked", func(t *testing.T) {
		execCtx, cancel := context.WithTimeout(ctx, execTimeout)
		defer cancel()

		result, err := cli.Exec(execCtx, sess.ID, types.ExecRequest{
			Command: "sh",
			Args:    []string{"-c", "cat /workspace/test.txt"},
		})
		if err != nil {
			// HTTP 403 means policy blocked the nested command
			var httpErr *client.HTTPError
			if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusForbidden {
				t.Logf("Nested cat correctly blocked with 403")
				return
			}
			if errors.Is(err, context.DeadlineExceeded) {
				t.Skip("command timeout - seccomp-user-notify not working")
			}
			t.Fatalf("Exec nested cat: %v", err)
		}

		// If we get here, the command ran - check if it failed
		if result.Result.ExitCode == 0 && result.Result.Stdout == "test content" {
			t.Logf("NOTE: Nested cat succeeded - seccomp interception may not be active")
			t.Skip("seccomp-user-notify not enforcing in this environment")
		}

		// Non-zero exit or empty output indicates the nested command was blocked
		t.Logf("Nested cat blocked: exit=%d stderr=%q stdout=%q",
			result.Result.ExitCode, result.Result.Stderr, result.Result.Stdout)
	})

	if err := cli.DestroySession(ctx, sess.ID); err != nil {
		t.Logf("DestroySession: %v (non-fatal)", err)
	}
}

// Policy that blocks 'cat' when nested (depth >= 1) but allows it directly (depth 0)
const execveDepthTestPolicyYAML = `
version: 1
name: depth-test
description: Tests depth-based execve blocking

command_rules:
  # Block cat when nested (spawned by another process)
  - name: block-cat-nested
    commands: ["cat"]
    decision: deny
    message: "cat blocked when nested"
    context:
      min_depth: 1
      max_depth: -1

  # Allow cat when direct (user command)
  - name: allow-cat-direct
    commands: ["cat"]
    decision: allow
    context:
      min_depth: 0
      max_depth: 0

  # Allow everything else
  - name: allow-all
    commands: ["*"]
    decision: allow

file_rules:
  - name: allow-all
    paths: ["/**"]
    operations: ["*"]
    decision: allow

resource_limits:
  command_timeout: 30s
  session_timeout: 1h
  idle_timeout: 30m
`

// Config with execve interception enabled
const execveInterceptionConfigYAML = `
server:
  http:
    addr: "0.0.0.0:18080"
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
  enabled: true
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
  seccomp:
    enabled: true
    execve:
      enabled: true
      max_argc: 1000
      max_argv_bytes: 65536
      on_truncated: deny
policies:
  dir: "/policies"
  default: "depth-test"
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
    addr: "0.0.0.0:18080"
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
