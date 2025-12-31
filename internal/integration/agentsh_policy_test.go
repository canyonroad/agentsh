//go:build integration

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
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/docker/docker/api/types/container"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestPolicyAllowAndDenyCommands(t *testing.T) {
	ctx := context.Background()

	bin := buildAgentshBinary(t)
	temp := t.TempDir()

	policiesDir := filepath.Join(temp, "policies")
	mustMkdir(t, policiesDir)
	writeFile(t, filepath.Join(policiesDir, "default.yaml"), testPolicyYAML)

	keysPath := filepath.Join(temp, "keys.yaml")
	writeFile(t, keysPath, testAPIKeysYAML)

	configPath := filepath.Join(temp, "config.yaml")
	writeFile(t, configPath, testConfigTemplate)

	workspace := filepath.Join(temp, "workspace")
	mustMkdir(t, workspace)
	writeFile(t, filepath.Join(workspace, "file.txt"), "hello")

	endpoint, cleanup := startServerContainer(t, ctx, bin, configPath, policiesDir, workspace)
	t.Cleanup(func() { cleanup() })

	cli := client.New(endpoint, "test-key")

	sess, err := cli.CreateSession(ctx, "/workspace", "default")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	allowResp, err := cli.Exec(ctx, sess.ID, types.ExecRequest{
		Command: "echo",
		Args:    []string{"ok"},
	})
	if err != nil {
		t.Fatalf("Exec allow: %v", err)
	}
	if allowResp.Result.ExitCode != 0 || allowResp.Result.Stdout != "ok\n" {
		t.Fatalf("allow command unexpected result: %+v", allowResp.Result)
	}

	_, err = cli.Exec(ctx, sess.ID, types.ExecRequest{
		Command: "cat",
		Args:    []string{"/workspace/file.txt"},
	})
	var httpErr *client.HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusForbidden {
		t.Fatalf("expected policy deny 403, got %v", err)
	}

	if err := cli.DestroySession(ctx, sess.ID); err != nil {
		t.Fatalf("DestroySession: %v", err)
	}
}

func buildAgentshBinary(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "agentsh")
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

	cmd := exec.Command("go", "build", "-o", out, "./cmd/agentsh")
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	if outEnv := os.Getenv("GOEXPERIMENT"); outEnv != "" {
		cmd.Env = append(cmd.Env, "GOEXPERIMENT="+outEnv)
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("go build agentsh: %v", err)
	}
	return out
}

func startServerContainer(t *testing.T, ctx context.Context, bin, configPath, policiesDir, workspace string) (string, func()) {
	t.Helper()

	binds := []testcontainers.ContainerMount{
		testcontainers.BindMount(bin, "/usr/local/bin/agentsh"),
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
			WithPort("8080/tcp").
			WithStartupTimeout(60 * time.Second).
			WithStatusCodeMatcher(func(code int) bool { return code == http.StatusOK || code == http.StatusNotFound }),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		if container != nil {
			if logs, logErr := container.Logs(ctx); logErr == nil {
				defer logs.Close()
				b, _ := io.ReadAll(logs)
				t.Logf("container logs:\n%s", string(b))
			} else {
				t.Logf("container logs unavailable: %v", logErr)
			}
		}
		t.Fatalf("start container: %v", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("container host: %v", err)
	}
	mappedPort, err := container.MappedPort(ctx, "8080/tcp")
	if err != nil {
		t.Fatalf("map port: %v", err)
	}
	endpoint := fmt.Sprintf("http://%s:%s", host, mappedPort.Port())

	cleanup := func() {
		_ = container.Terminate(context.Background())
	}
	return endpoint, cleanup
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

func writeFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

const testPolicyYAML = `
version: 1
name: default
description: integration test policy
command_rules:
  - name: deny-cat
    commands: ["cat"]
    decision: deny
    message: "cat is blocked"
  - name: allow-echo
    commands: ["echo"]
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

const testAPIKeysYAML = `
- id: test
  key: test-key
  description: integration test key
  role: admin
`

const testConfigTemplate = `
server:
  http:
    addr: "0.0.0.0:8080"
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
policies:
  dir: "/policies"
  default: "default"
approvals:
  enabled: false
metrics:
  enabled: false
health:
  path: "/health"
`
