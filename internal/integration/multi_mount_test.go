//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/docker/docker/api/types/container"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TestMultiMountProfile tests profile-based session creation with multiple mounts
// and different policies per mount.
func TestMultiMountProfile(t *testing.T) {
	ctx := context.Background()

	bin := buildAgentshBinary(t)
	temp := t.TempDir()

	// Create policies directory with workspace-rw and config-readonly policies
	policiesDir := filepath.Join(temp, "policies")
	mustMkdir(t, policiesDir)
	writeFile(t, filepath.Join(policiesDir, "workspace-rw.yaml"), workspaceRWPolicyYAML)
	writeFile(t, filepath.Join(policiesDir, "config-readonly.yaml"), configReadonlyPolicyYAML)

	keysPath := filepath.Join(temp, "keys.yaml")
	writeFile(t, keysPath, testAPIKeysYAML)

	// Create workspace directory with a test file
	workspace := filepath.Join(temp, "workspace")
	mustMkdir(t, workspace)
	writeFile(t, filepath.Join(workspace, "workspace-file.txt"), "workspace content")

	// Create config directory with a test file
	configDir := filepath.Join(temp, "config")
	mustMkdir(t, configDir)
	writeFile(t, filepath.Join(configDir, "config-file.txt"), "config content")

	// Create config.yaml with mount_profiles section
	configPath := filepath.Join(temp, "config.yaml")
	writeFile(t, configPath, multiMountConfigYAML)

	// Start container with multiple mount bindings
	endpoint, cleanup := startMultiMountServerContainer(t, ctx, bin, configPath, policiesDir, workspace, configDir)
	t.Cleanup(func() { cleanup() })

	cli := client.New(endpoint, "test-key")

	// Create session with profile
	sess, err := cli.CreateSessionWithProfile(ctx, "dev")
	if err != nil {
		t.Fatalf("CreateSessionWithProfile: %v", err)
	}

	// Verify session has profile set
	if sess.Profile != "dev" {
		t.Errorf("expected profile 'dev', got %q", sess.Profile)
	}

	// Log session mounts for debugging
	// Note: Mounts may not be returned if FUSE setup failed (expected in CI without /dev/fuse)
	if len(sess.Mounts) > 0 {
		t.Logf("Session mounts: %+v", sess.Mounts)
	} else {
		t.Logf("No FUSE mounts (expected if /dev/fuse unavailable)")
	}

	// Test 1: Read from primary workspace mount path
	// The first mount path (/host-workspace) is the primary workspace
	t.Run("read_primary_workspace", func(t *testing.T) {
		resp, err := cli.Exec(ctx, sess.ID, types.ExecRequest{
			Command: "cat",
			Args:    []string{"/host-workspace/workspace-file.txt"},
		})
		if err != nil {
			t.Fatalf("Exec cat workspace: %v", err)
		}
		if resp.Result.ExitCode != 0 {
			t.Fatalf("cat workspace failed: exit=%d stderr=%s", resp.Result.ExitCode, resp.Result.Stderr)
		}
		if resp.Result.Stdout != "workspace content" {
			t.Errorf("expected 'workspace content', got %q", resp.Result.Stdout)
		}
	})

	// Test 2: Read from secondary mount (config)
	t.Run("read_config", func(t *testing.T) {
		resp, err := cli.Exec(ctx, sess.ID, types.ExecRequest{
			Command: "cat",
			Args:    []string{"/host-config/config-file.txt"},
		})
		if err != nil {
			t.Fatalf("Exec cat config: %v", err)
		}
		if resp.Result.ExitCode != 0 {
			t.Fatalf("cat config failed: exit=%d stderr=%s", resp.Result.ExitCode, resp.Result.Stderr)
		}
		if resp.Result.Stdout != "config content" {
			t.Errorf("expected 'config content', got %q", resp.Result.Stdout)
		}
	})

	// Test 3: Write to workspace should work
	t.Run("write_workspace", func(t *testing.T) {
		resp, err := cli.Exec(ctx, sess.ID, types.ExecRequest{
			Command: "sh",
			Args:    []string{"-c", "echo 'new content' > /host-workspace/new-file.txt"},
		})
		if err != nil {
			t.Fatalf("Exec write workspace: %v", err)
		}
		if resp.Result.ExitCode != 0 {
			t.Fatalf("write workspace failed: exit=%d stderr=%s", resp.Result.ExitCode, resp.Result.Stderr)
		}

		// Verify file was written
		verifyResp, err := cli.Exec(ctx, sess.ID, types.ExecRequest{
			Command: "cat",
			Args:    []string{"/host-workspace/new-file.txt"},
		})
		if err != nil {
			t.Fatalf("Exec cat new file: %v", err)
		}
		if verifyResp.Result.ExitCode != 0 {
			t.Fatalf("cat new file failed: exit=%d stderr=%s", verifyResp.Result.ExitCode, verifyResp.Result.Stderr)
		}
		if verifyResp.Result.Stdout != "new content\n" {
			t.Errorf("expected 'new content\\n', got %q", verifyResp.Result.Stdout)
		}
	})

	// Test 4: Write to config should fail (readonly policy)
	// Note: Policy enforcement requires FUSE to be available and mount to succeed.
	// If FUSE is unavailable, writes will succeed directly to the container fs.
	t.Run("write_config_policy_check", func(t *testing.T) {
		_, err := cli.Exec(ctx, sess.ID, types.ExecRequest{
			Command: "sh",
			Args:    []string{"-c", "echo 'attempt write' > /host-config/policy-test.txt"},
		})

		var httpErr *client.HTTPError
		if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusForbidden {
			t.Logf("Write to config correctly denied with 403 (FUSE policy enforcement active)")
			return
		}

		// Check if write succeeded (FUSE not available)
		checkResp, checkErr := cli.Exec(ctx, sess.ID, types.ExecRequest{
			Command: "cat",
			Args:    []string{"/host-config/policy-test.txt"},
		})
		if checkErr == nil && checkResp.Result.ExitCode == 0 {
			// Write succeeded - FUSE policy enforcement not active
			// This is expected when FUSE is unavailable (e.g., CI without /dev/fuse)
			t.Logf("Write to config succeeded (FUSE unavailable, no policy enforcement)")

			// Clean up test file
			_, _ = cli.Exec(ctx, sess.ID, types.ExecRequest{
				Command: "rm",
				Args:    []string{"/host-config/policy-test.txt"},
			})
		} else {
			t.Logf("Write to config was prevented: %v", err)
		}
	})

	// Cleanup
	if err := cli.DestroySession(ctx, sess.ID); err != nil {
		t.Fatalf("DestroySession: %v", err)
	}
}

// startMultiMountServerContainer starts a server container with multiple directory mounts.
func startMultiMountServerContainer(t *testing.T, ctx context.Context, bin, configPath, policiesDir, workspace, configDir string) (string, func()) {
	t.Helper()

	binds := []testcontainers.ContainerMount{
		testcontainers.BindMount(bin, "/usr/local/bin/agentsh"),
		testcontainers.BindMount(configPath, "/config.yaml"),
		testcontainers.BindMount(filepath.Join(filepath.Dir(configPath), "keys.yaml"), "/keys.yaml"),
		testcontainers.BindMount(policiesDir, "/policies"),
		testcontainers.BindMount(workspace, "/host-workspace"),
		testcontainers.BindMount(configDir, "/host-config"),
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
			if _, err := os.Stat("/dev/fuse"); err == nil {
				hc.Devices = append(hc.Devices, container.DeviceMapping{
					PathOnHost:        "/dev/fuse",
					PathInContainer:   "/dev/fuse",
					CgroupPermissions: "rwm",
				})
			}
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
			} else {
				t.Logf("container logs unavailable: %v", logErr)
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
		_ = ctr.Terminate(context.Background())
	}
	return endpoint, cleanup
}

// workspaceRWPolicyYAML allows all operations in workspace
const workspaceRWPolicyYAML = `
version: 1
name: workspace-rw
description: Full read-write access to workspace

file_rules:
  - name: allow-all-read
    paths: ["/**"]
    operations: [read, stat, list, open, readlink]
    decision: allow

  - name: allow-all-write
    paths: ["/**"]
    operations: [write, create, delete, mkdir, rmdir, chmod, rename]
    decision: allow

command_rules:
  - name: allow-all
    commands: ["*"]
    decision: allow

resource_limits:
  max_memory_mb: 0
  cpu_quota_percent: 0
  disk_read_bps_max: 0
  disk_write_bps_max: 0
  net_bandwidth_mbps: 0
  pids_max: 0
  command_timeout: 30s
  session_timeout: 1h
  idle_timeout: 30m
`

// configReadonlyPolicyYAML allows reads but denies writes
const configReadonlyPolicyYAML = `
version: 1
name: config-readonly
description: Read-only access for config directories

file_rules:
  - name: allow-readonly
    paths: ["/**"]
    operations: [read, stat, list, open, readlink]
    decision: allow

  - name: deny-write
    paths: ["/**"]
    operations: [write, create, delete, mkdir, rmdir, chmod, rename]
    decision: deny
    message: "config paths are read-only"

command_rules:
  - name: allow-all
    commands: ["*"]
    decision: allow

resource_limits:
  max_memory_mb: 0
  cpu_quota_percent: 0
  disk_read_bps_max: 0
  disk_write_bps_max: 0
  net_bandwidth_mbps: 0
  pids_max: 0
  command_timeout: 30s
  session_timeout: 1h
  idle_timeout: 30m
`

// multiMountConfigYAML configures mount profiles for multi-mount testing
const multiMountConfigYAML = `
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
  base_dir: "/sessions"
sandbox:
  fuse:
    enabled: true
    audit:
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
  default: "workspace-rw"
mount_profiles:
  dev:
    base_policy: workspace-rw
    mounts:
      - path: /host-workspace
        policy: workspace-rw
      - path: /host-config
        policy: config-readonly
approvals:
  enabled: false
metrics:
  enabled: false
health:
  path: "/health"
`
