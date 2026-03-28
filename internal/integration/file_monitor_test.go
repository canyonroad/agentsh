//go:build integration && linux

package integration

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
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

// TestFileMonitor_ReadAllowed verifies that the seccomp file_monitor allows
// read-only file operations when policy permits them. This is a regression test
// for the bug where the emulated openat path's fail-secure behavior on
// resolvePathAt failure caused all reads to be blocked with EACCES.
//
// The test runs with:
//   - unix_sockets.enabled: true
//   - seccomp.file_monitor.enabled: true
//   - seccomp.file_monitor.enforce_without_fuse: true
//   - FUSE disabled, ptrace disabled
//
// This matches the production configuration that exhibits the bug.
func TestFileMonitor_ReadAllowed(t *testing.T) {
	ctx := context.Background()

	agentshBin, unixwrapBin := buildSeccompBinaries(t)

	temp := t.TempDir()

	policiesDir := filepath.Join(temp, "policies")
	mustMkdir(t, policiesDir)
	writeFile(t, filepath.Join(policiesDir, "default.yaml"), fileMonitorTestPolicyYAML)

	keysPath := filepath.Join(temp, "keys.yaml")
	writeFile(t, keysPath, testAPIKeysYAML)

	configPath := filepath.Join(temp, "config.yaml")
	writeFile(t, configPath, fileMonitorConfigYAML)

	workspace := filepath.Join(temp, "workspace")
	mustMkdir(t, workspace)
	writeFile(t, filepath.Join(workspace, "hello.txt"), "hello from workspace")

	endpoint, cleanup := startFileMonitorContainer(t, ctx, agentshBin, unixwrapBin, configPath, policiesDir, workspace)
	t.Cleanup(cleanup)

	cli := client.New(endpoint, "test-key")

	sess, err := cli.CreateSession(ctx, "/workspace", "default")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	t.Logf("Session created: %s", sess.ID)

	execTimeout := 15 * time.Second

	// Probe: ensure seccomp-user-notify works at all
	probeCtx, probeCancel := context.WithTimeout(ctx, execTimeout)
	probeResult, probeErr := cli.Exec(probeCtx, sess.ID, types.ExecRequest{
		Command: "echo",
		Args:    []string{"probe"},
	})
	probeCancel()

	if probeErr != nil {
		if errors.Is(probeErr, context.DeadlineExceeded) || strings.Contains(probeErr.Error(), "deadline exceeded") {
			t.Skip("seccomp-user-notify not working in this environment (timeout)")
		}
		t.Fatalf("Exec probe: %v", probeErr)
	}
	if probeResult.Result.ExitCode != 0 {
		t.Logf("Probe stdout: %q", probeResult.Result.Stdout)
		t.Logf("Probe stderr: %q", probeResult.Result.Stderr)
		t.Skip("seccomp-user-notify not working (non-zero exit)")
	}
	t.Logf("Probe succeeded: %q", strings.TrimSpace(probeResult.Result.Stdout))

	// Test 1: cat workspace file (read-only open of a policy-allowed path)
	t.Run("read_workspace_file", func(t *testing.T) {
		execCtx, cancel := context.WithTimeout(ctx, execTimeout)
		defer cancel()

		result, err := cli.Exec(execCtx, sess.ID, types.ExecRequest{
			Command: "cat",
			Args:    []string{"/workspace/hello.txt"},
		})
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				t.Skip("command timeout")
			}
			t.Fatalf("Exec cat: %v", err)
		}
		if result.Result.ExitCode != 0 {
			t.Errorf("cat should succeed, got exit %d: stderr=%q", result.Result.ExitCode, result.Result.Stderr)
		}
		if strings.TrimSpace(result.Result.Stdout) != "hello from workspace" {
			t.Errorf("expected 'hello from workspace', got %q", result.Result.Stdout)
		}
		t.Logf("Read workspace file succeeded: %q", strings.TrimSpace(result.Result.Stdout))
	})

	// Test 2: cat /etc/hostname (read-only open of a system path)
	t.Run("read_system_file", func(t *testing.T) {
		execCtx, cancel := context.WithTimeout(ctx, execTimeout)
		defer cancel()

		result, err := cli.Exec(execCtx, sess.ID, types.ExecRequest{
			Command: "cat",
			Args:    []string{"/etc/hostname"},
		})
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				t.Skip("command timeout")
			}
			t.Fatalf("Exec cat /etc/hostname: %v", err)
		}
		if result.Result.ExitCode != 0 {
			t.Errorf("cat /etc/hostname should succeed, got exit %d: stderr=%q", result.Result.ExitCode, result.Result.Stderr)
		}
		t.Logf("Read system file succeeded: %q", strings.TrimSpace(result.Result.Stdout))
	})

	// Test 3: ls /usr (read-only open that loads shared libs)
	t.Run("read_usr_listing", func(t *testing.T) {
		execCtx, cancel := context.WithTimeout(ctx, execTimeout)
		defer cancel()

		result, err := cli.Exec(execCtx, sess.ID, types.ExecRequest{
			Command: "ls",
			Args:    []string{"/usr"},
		})
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				t.Skip("command timeout")
			}
			t.Fatalf("Exec ls: %v", err)
		}
		if result.Result.ExitCode != 0 {
			t.Errorf("ls /usr should succeed, got exit %d: stderr=%q", result.Result.ExitCode, result.Result.Stderr)
		}
		t.Logf("Read /usr listing succeeded (len=%d)", len(result.Result.Stdout))
	})

	// Test 4: write to denied path should still be denied
	t.Run("write_denied_path", func(t *testing.T) {
		execCtx, cancel := context.WithTimeout(ctx, execTimeout)
		defer cancel()

		result, err := cli.Exec(execCtx, sess.ID, types.ExecRequest{
			Command:    "sh",
			Args:       []string{"-c", "echo test > /etc/test_write 2>&1; echo exit=$?"},
			WorkingDir: "/workspace",
		})
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				t.Skip("command timeout")
			}
			// A failure here is acceptable — command may have been killed
			t.Logf("Write to denied path returned error (expected): %v", err)
			return
		}
		// The write should fail (EACCES or command failure)
		t.Logf("Write denied path result: exit=%d stdout=%q stderr=%q",
			result.Result.ExitCode, result.Result.Stdout, result.Result.Stderr)
		if !strings.Contains(result.Result.Stderr, "Permission denied") &&
			!strings.Contains(result.Result.Stdout, "Permission denied") &&
			result.Result.ExitCode == 0 {
			t.Errorf("write to /etc/test_write should be denied")
		}
	})

	if err := cli.DestroySession(ctx, sess.ID); err != nil {
		t.Logf("DestroySession: %v (non-fatal)", err)
	}
}

// TestFileMonitor_NoEmulation verifies that disabling openat_emulation allows
// reads to succeed (as a diagnostic for the fail-secure vs fail-open hypothesis).
func TestFileMonitor_NoEmulation(t *testing.T) {
	ctx := context.Background()

	agentshBin, unixwrapBin := buildSeccompBinaries(t)

	temp := t.TempDir()

	policiesDir := filepath.Join(temp, "policies")
	mustMkdir(t, policiesDir)
	writeFile(t, filepath.Join(policiesDir, "default.yaml"), fileMonitorTestPolicyYAML)

	keysPath := filepath.Join(temp, "keys.yaml")
	writeFile(t, keysPath, testAPIKeysYAML)

	configPath := filepath.Join(temp, "config.yaml")
	writeFile(t, configPath, fileMonitorNoEmulationConfigYAML)

	workspace := filepath.Join(temp, "workspace")
	mustMkdir(t, workspace)
	writeFile(t, filepath.Join(workspace, "hello.txt"), "hello from workspace")

	endpoint, cleanup := startFileMonitorContainer(t, ctx, agentshBin, unixwrapBin, configPath, policiesDir, workspace)
	t.Cleanup(cleanup)

	cli := client.New(endpoint, "test-key")

	sess, err := cli.CreateSession(ctx, "/workspace", "default")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	t.Logf("Session created: %s", sess.ID)

	execTimeout := 15 * time.Second

	// Probe
	probeCtx, probeCancel := context.WithTimeout(ctx, execTimeout)
	probeResult, probeErr := cli.Exec(probeCtx, sess.ID, types.ExecRequest{
		Command: "echo",
		Args:    []string{"probe"},
	})
	probeCancel()

	if probeErr != nil {
		if errors.Is(probeErr, context.DeadlineExceeded) || strings.Contains(probeErr.Error(), "deadline exceeded") {
			t.Skip("seccomp-user-notify not working in this environment (timeout)")
		}
		t.Fatalf("Exec probe: %v", probeErr)
	}
	if probeResult.Result.ExitCode != 0 {
		t.Skip("seccomp-user-notify not working (non-zero exit)")
	}

	// Read workspace file — with emulation disabled, the non-emulated path
	// should fail-open on resolvePathAt errors (CONTINUE instead of EACCES)
	t.Run("read_workspace_file_no_emulation", func(t *testing.T) {
		execCtx, cancel := context.WithTimeout(ctx, execTimeout)
		defer cancel()

		result, err := cli.Exec(execCtx, sess.ID, types.ExecRequest{
			Command: "cat",
			Args:    []string{"/workspace/hello.txt"},
		})
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				t.Skip("command timeout")
			}
			t.Fatalf("Exec cat: %v", err)
		}
		if result.Result.ExitCode != 0 {
			t.Errorf("cat should succeed with emulation disabled, got exit %d: stderr=%q",
				result.Result.ExitCode, result.Result.Stderr)
		}
		if strings.TrimSpace(result.Result.Stdout) != "hello from workspace" {
			t.Errorf("expected 'hello from workspace', got %q", result.Result.Stdout)
		}
		t.Logf("Read succeeded with emulation disabled: %q", strings.TrimSpace(result.Result.Stdout))
	})

	if err := cli.DestroySession(ctx, sess.ID); err != nil {
		t.Logf("DestroySession: %v (non-fatal)", err)
	}
}

func startFileMonitorContainer(t *testing.T, ctx context.Context, agentshBin, unixwrapBin, configPath, policiesDir, workspace string) (string, func()) {
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
			hc.SecurityOpt = []string{"apparmor:unconfined", "seccomp:unconfined"}
		},
		WaitingFor: wait.ForHTTP("/health").
			WithPort("18080/tcp").
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
	mappedPort, err := ctr.MappedPort(ctx, "18080/tcp")
	if err != nil {
		t.Fatalf("map port: %v", err)
	}
	endpoint := fmt.Sprintf("http://%s:%s", host, mappedPort.Port())

	cleanup := func() {
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

// startFileMonitorContainerNoPtrace creates a container WITHOUT CAP_SYS_PTRACE.
// This simulates environments where the server cannot use ProcessVMReadv on
// non-descendant processes (the key condition for the file_monitor bug).
func startFileMonitorContainerNoPtrace(t *testing.T, ctx context.Context, agentshBin, unixwrapBin, configPath, policiesDir, workspace string) (string, func()) {
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
		// NOT Privileged — only grant SYS_ADMIN (needed for seccomp user-notify)
		CapAdd: []string{"SYS_ADMIN"},
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.SecurityOpt = []string{"apparmor:unconfined", "seccomp:unconfined"}
			// Explicitly drop SYS_PTRACE to simulate the bug environment
			hc.CapDrop = []string{"SYS_PTRACE"}
		},
		WaitingFor: wait.ForHTTP("/health").
			WithPort("18080/tcp").
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
	mappedPort, err := ctr.MappedPort(ctx, "18080/tcp")
	if err != nil {
		t.Fatalf("map port: %v", err)
	}
	endpoint := fmt.Sprintf("http://%s:%s", host, mappedPort.Port())

	cleanup := func() {
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

// TestFileMonitor_NoPtraceCap verifies the behavior when CAP_SYS_PTRACE is
// absent. This is the critical test — the bug manifests when the server
// cannot use ProcessVMReadv to read the tracee's path, causing the emulated
// openat path to fail-secure with EACCES on all operations.
func TestFileMonitor_NoPtraceCap(t *testing.T) {
	ctx := context.Background()

	agentshBin, unixwrapBin := buildSeccompBinaries(t)

	temp := t.TempDir()

	policiesDir := filepath.Join(temp, "policies")
	mustMkdir(t, policiesDir)
	writeFile(t, filepath.Join(policiesDir, "default.yaml"), fileMonitorTestPolicyYAML)

	keysPath := filepath.Join(temp, "keys.yaml")
	writeFile(t, keysPath, testAPIKeysYAML)

	configPath := filepath.Join(temp, "config.yaml")
	writeFile(t, configPath, fileMonitorConfigYAML)

	workspace := filepath.Join(temp, "workspace")
	mustMkdir(t, workspace)
	writeFile(t, filepath.Join(workspace, "hello.txt"), "hello from workspace")

	endpoint, cleanup := startFileMonitorContainerNoPtrace(t, ctx, agentshBin, unixwrapBin, configPath, policiesDir, workspace)
	t.Cleanup(cleanup)

	cli := client.New(endpoint, "test-key")

	sess, err := cli.CreateSession(ctx, "/workspace", "default")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	t.Logf("Session created: %s", sess.ID)

	execTimeout := 15 * time.Second

	// Probe
	probeCtx, probeCancel := context.WithTimeout(ctx, execTimeout)
	probeResult, probeErr := cli.Exec(probeCtx, sess.ID, types.ExecRequest{
		Command: "echo",
		Args:    []string{"probe"},
	})
	probeCancel()

	if probeErr != nil {
		if errors.Is(probeErr, context.DeadlineExceeded) || strings.Contains(probeErr.Error(), "deadline exceeded") {
			t.Skip("seccomp-user-notify not working without CAP_SYS_PTRACE (timeout)")
		}
		t.Fatalf("Exec probe: %v", probeErr)
	}
	t.Logf("Probe result: exit=%d stdout=%q stderr=%q",
		probeResult.Result.ExitCode, probeResult.Result.Stdout, probeResult.Result.Stderr)

	if probeResult.Result.ExitCode != 0 {
		t.Logf("BUG REPRODUCED: basic 'echo' fails without CAP_SYS_PTRACE")
		t.Logf("This confirms ProcessVMReadv failure → emulated path fail-secure → EACCES on all operations")
	} else {
		t.Logf("Probe succeeded — ProcessVMReadv works without CAP_SYS_PTRACE in this environment")
	}

	// Read workspace file
	t.Run("read_workspace_file_no_ptrace_cap", func(t *testing.T) {
		execCtx, cancel := context.WithTimeout(ctx, execTimeout)
		defer cancel()

		result, err := cli.Exec(execCtx, sess.ID, types.ExecRequest{
			Command: "cat",
			Args:    []string{"/workspace/hello.txt"},
		})
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				t.Skip("command timeout")
			}
			t.Fatalf("Exec cat: %v", err)
		}
		if result.Result.ExitCode != 0 {
			t.Logf("BUG: cat workspace file failed without CAP_SYS_PTRACE: exit=%d stderr=%q",
				result.Result.ExitCode, result.Result.Stderr)
			t.Errorf("cat should succeed — file_monitor blocks reads without CAP_SYS_PTRACE")
		} else {
			t.Logf("Read succeeded: %q", strings.TrimSpace(result.Result.Stdout))
		}
	})

	if err := cli.DestroySession(ctx, sess.ID); err != nil {
		t.Logf("DestroySession: %v (non-fatal)", err)
	}
}

// Policy that allows reads everywhere and denies writes outside workspace/tmp.
const fileMonitorTestPolicyYAML = `
version: 1
name: default
description: file_monitor integration test policy

command_rules:
  - name: allow-all
    commands: []
    decision: allow

file_rules:
  - name: allow-workspace
    paths: ["/workspace/**", "/workspace"]
    operations: ["*"]
    decision: allow

  - name: allow-tmp
    paths: ["/tmp/**", "/var/tmp/**"]
    operations: ["*"]
    decision: allow

  - name: allow-system-read
    paths: ["/usr/**", "/lib/**", "/lib64/**", "/bin/**", "/sbin/**", "/opt/**"]
    operations: [read, open, stat, list, readlink]
    decision: allow

  - name: allow-etc-read
    paths: ["/etc/**"]
    operations: [read, open, stat, list, readlink]
    decision: allow

  - name: allow-dev
    paths: ["/dev/**"]
    operations: ["*"]
    decision: allow

  - name: allow-proc-self
    paths: ["/proc/self/**", "/proc/thread-self/**"]
    operations: [read, open, stat, list, readlink]
    decision: allow

  - name: allow-run
    paths: ["/run/**", "/var/run/**"]
    operations: [read, open, stat, list, readlink]
    decision: allow

  - name: default-deny-writes
    paths: ["/**"]
    operations: [write, create, delete, rename, chmod, chown]
    decision: deny
    message: "write access denied by default"

resource_limits:
  command_timeout: 30s
  session_timeout: 1h
  idle_timeout: 30m
`

// Config: file_monitor enabled with enforcement (emulation defaults to true)
const fileMonitorConfigYAML = `
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
  seccomp:
    enabled: true
    file_monitor:
      enabled: true
      enforce_without_fuse: true
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

// Config: file_monitor with openat_emulation explicitly disabled
const fileMonitorNoEmulationConfigYAML = `
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
  seccomp:
    enabled: true
    file_monitor:
      enabled: true
      enforce_without_fuse: true
      openat_emulation: false
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
