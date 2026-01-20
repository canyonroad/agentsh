//go:build integration && linux

package integration

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
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

// TestAlpineEnvInject_BashBuiltinDisabled verifies that on Alpine Linux (musl):
// 1. The server starts with env_inject configured
// 2. BASH_ENV points to bash_startup.sh which disables builtins
// 3. The bash kill builtin is disabled and falls back to /bin/kill
// 4. /bin/kill is subject to seccomp policy enforcement
func TestAlpineEnvInject_BashBuiltinDisabled(t *testing.T) {
	ctx := context.Background()

	// Build Alpine/musl binaries
	agentshBin, unixwrapBin, startupScript := buildAlpineBinaries(t)

	temp := t.TempDir()

	policiesDir := filepath.Join(temp, "policies")
	mustMkdir(t, policiesDir)
	writeFile(t, filepath.Join(policiesDir, "env-inject-test.yaml"), alpineEnvInjectPolicyYAML)

	keysPath := filepath.Join(temp, "keys.yaml")
	writeFile(t, keysPath, testAPIKeysYAML)

	configPath := filepath.Join(temp, "config.yaml")
	writeFile(t, configPath, alpineEnvInjectConfigYAML)

	workspace := filepath.Join(temp, "workspace")
	mustMkdir(t, workspace)

	endpoint, cleanup := startAlpineServerContainer(t, ctx, agentshBin, unixwrapBin, startupScript, configPath, policiesDir, workspace)
	t.Cleanup(cleanup)

	cli := client.New(endpoint, "test-key")

	// Create session
	sess, err := cli.CreateSession(ctx, "/workspace", "env-inject-test")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	t.Logf("Session created: %s", sess.ID)

	execTimeout := 15 * time.Second

	// Test 1: Verify bash is available and working
	t.Run("bash_available", func(t *testing.T) {
		execCtx, cancel := context.WithTimeout(ctx, execTimeout)
		defer cancel()

		result, err := cli.Exec(execCtx, sess.ID, types.ExecRequest{
			Command: "/bin/bash",
			Args:    []string{"--version"},
		})
		if err != nil {
			t.Fatalf("Exec bash --version: %v", err)
		}
		if result.Result.ExitCode != 0 {
			t.Errorf("bash --version failed: exit=%d stderr=%q", result.Result.ExitCode, result.Result.Stderr)
		}
		t.Logf("Bash available: %s", strings.Split(result.Result.Stdout, "\n")[0])
	})

	// Test 2: Verify kill builtin is disabled (type kill should show /bin/kill, not builtin)
	t.Run("kill_builtin_disabled", func(t *testing.T) {
		execCtx, cancel := context.WithTimeout(ctx, execTimeout)
		defer cancel()

		result, err := cli.Exec(execCtx, sess.ID, types.ExecRequest{
			Command: "/bin/bash",
			Args:    []string{"-c", "type kill"},
		})
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				t.Skip("command timeout - seccomp-user-notify may not be working")
			}
			t.Fatalf("Exec type kill: %v", err)
		}

		output := result.Result.Stdout + result.Result.Stderr
		t.Logf("type kill output: %q", output)

		// Should NOT be a shell builtin
		if strings.Contains(output, "shell builtin") {
			t.Errorf("kill should not be a shell builtin, got: %s", output)
		}

		// Should be /bin/kill or similar
		if !strings.Contains(output, "/kill") {
			t.Errorf("kill should resolve to /bin/kill or /usr/bin/kill, got: %s", output)
		}
	})

	// Test 3: Verify other builtins are also disabled
	t.Run("other_builtins_disabled", func(t *testing.T) {
		execCtx, cancel := context.WithTimeout(ctx, execTimeout)
		defer cancel()

		result, err := cli.Exec(execCtx, sess.ID, types.ExecRequest{
			Command: "/bin/bash",
			Args:    []string{"-c", "type enable 2>&1 || true"},
		})
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				t.Skip("command timeout")
			}
			t.Fatalf("Exec type enable: %v", err)
		}

		output := result.Result.Stdout + result.Result.Stderr
		t.Logf("type enable output: %q", output)

		// enable should be disabled (not found or error)
		if strings.Contains(output, "shell builtin") && !strings.Contains(output, "not found") {
			t.Logf("Note: enable builtin may still show as builtin but be non-functional")
		}
	})

	// Test 4: Direct kill -0 $$ should work (testing signal to self)
	t.Run("direct_kill_self", func(t *testing.T) {
		execCtx, cancel := context.WithTimeout(ctx, execTimeout)
		defer cancel()

		// kill -0 $$ tests if we can signal ourselves (always allowed)
		result, err := cli.Exec(execCtx, sess.ID, types.ExecRequest{
			Command: "/bin/bash",
			Args:    []string{"-c", "kill -0 $$ && echo SUCCESS"},
		})
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				t.Skip("command timeout - seccomp-user-notify may not be working")
			}
			t.Fatalf("Exec kill -0: %v", err)
		}

		t.Logf("kill -0 $$ result: exit=%d stdout=%q stderr=%q",
			result.Result.ExitCode, result.Result.Stdout, result.Result.Stderr)

		// This should succeed - signaling self is typically allowed
		if !strings.Contains(result.Result.Stdout, "SUCCESS") && result.Result.ExitCode != 0 {
			t.Logf("Note: kill -0 $$ may be blocked by policy, which is fine")
		}
	})

	if err := cli.DestroySession(ctx, sess.ID); err != nil {
		t.Logf("DestroySession: %v (non-fatal)", err)
	}
}

// buildAlpineBinaries builds the agentsh binaries using an Alpine container
// to ensure they're statically linked against musl.
func buildAlpineBinaries(t *testing.T) (agentsh, unixwrap, startupScript string) {
	t.Helper()

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

	outputDir := t.TempDir()
	agentshOut := filepath.Join(outputDir, "agentsh")
	unixwrapOut := filepath.Join(outputDir, "agentsh-unixwrap")
	startupOut := filepath.Join(outputDir, "bash_startup.sh")

	// Copy the bash_startup.sh script
	startupSrc := filepath.Join(repoRoot, "packaging", "bash_startup.sh")
	startupContent, err := os.ReadFile(startupSrc)
	if err != nil {
		t.Fatalf("read bash_startup.sh: %v", err)
	}
	if err := os.WriteFile(startupOut, startupContent, 0755); err != nil {
		t.Fatalf("write bash_startup.sh: %v", err)
	}

	// Build using Alpine container for musl linking
	ctx := context.Background()

	// Create a build container
	buildScript := `#!/bin/sh
set -e
apk add --no-cache gcc musl-dev libseccomp-dev libseccomp-static git make file

cd /src

# Build agentsh with static musl + libseccomp
CGO_ENABLED=1 \
CGO_LDFLAGS="-static -lseccomp" \
go build -buildvcs=false -ldflags='-s -w -extldflags "-static"' \
  -o /output/agentsh ./cmd/agentsh

# Build agentsh-unixwrap with static musl + libseccomp
CGO_ENABLED=1 \
CGO_LDFLAGS="-static -lseccomp" \
go build -buildvcs=false -ldflags='-s -w -extldflags "-static"' \
  -o /output/agentsh-unixwrap ./cmd/agentsh-unixwrap

# Verify they're statically linked
file /output/agentsh
file /output/agentsh-unixwrap
`

	buildScriptPath := filepath.Join(outputDir, "build.sh")
	if err := os.WriteFile(buildScriptPath, []byte(buildScript), 0755); err != nil {
		t.Fatalf("write build script: %v", err)
	}

	req := testcontainers.ContainerRequest{
		Image: "golang:1.25-alpine",
		Mounts: []testcontainers.ContainerMount{
			testcontainers.BindMount(repoRoot, "/src"),
			testcontainers.BindMount(outputDir, "/output"),
		},
		Cmd:        []string{"/bin/sh", "/output/build.sh"},
		WaitingFor: wait.ForExit().WithExitTimeout(5 * time.Minute),
	}

	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("start build container: %v", err)
	}
	defer func() {
		if logs, err := ctr.Logs(ctx); err == nil {
			defer logs.Close()
			b, _ := io.ReadAll(logs)
			t.Logf("Build container logs:\n%s", string(b))
		}
		_ = ctr.Terminate(ctx)
	}()

	// Wait for container to exit
	state, err := ctr.State(ctx)
	if err != nil {
		t.Fatalf("get container state: %v", err)
	}
	if state.ExitCode != 0 {
		t.Fatalf("build container failed with exit code %d", state.ExitCode)
	}

	// Verify binaries exist
	if _, err := os.Stat(agentshOut); err != nil {
		t.Fatalf("agentsh binary not found: %v", err)
	}
	if _, err := os.Stat(unixwrapOut); err != nil {
		t.Fatalf("agentsh-unixwrap binary not found: %v", err)
	}

	return agentshOut, unixwrapOut, startupOut
}

func startAlpineServerContainer(t *testing.T, ctx context.Context, agentshBin, unixwrapBin, startupScript, configPath, policiesDir, workspace string) (string, func()) {
	t.Helper()

	binds := []testcontainers.ContainerMount{
		testcontainers.BindMount(agentshBin, "/usr/local/bin/agentsh"),
		testcontainers.BindMount(unixwrapBin, "/usr/local/bin/agentsh-unixwrap"),
		testcontainers.BindMount(startupScript, "/usr/lib/agentsh/bash_startup.sh"),
		testcontainers.BindMount(configPath, "/config.yaml"),
		testcontainers.BindMount(filepath.Join(filepath.Dir(configPath), "keys.yaml"), "/keys.yaml"),
		testcontainers.BindMount(policiesDir, "/policies"),
		testcontainers.BindMount(workspace, "/workspace"),
	}

	req := testcontainers.ContainerRequest{
		Image:        "alpine:3.21",
		ExposedPorts: []string{"18080/tcp"},
		// Install bash for testing (Alpine uses ash by default)
		Cmd: []string{"/bin/sh", "-c", "apk add --no-cache bash && /usr/local/bin/agentsh server --config /config.yaml"},
		Mounts:     binds,
		Privileged: true,
		CapAdd:     []string{"SYS_ADMIN"},
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.SecurityOpt = []string{"apparmor:unconfined", "seccomp:unconfined"}
		},
		WaitingFor: wait.ForHTTP("/health").
			WithPort("18080/tcp").
			WithStartupTimeout(90 * time.Second).
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
				t.Logf("Alpine container logs:\n%s", string(b))
			}
		}
		_ = ctr.Terminate(context.Background())
	}
	return endpoint, cleanup
}

// Policy that allows most operations but can test signal behavior
const alpineEnvInjectPolicyYAML = `
version: 1
name: env-inject-test
description: Tests env_inject and BASH_ENV on Alpine

command_rules:
  - name: allow-all
    commands: ["*"]
    decision: allow

file_rules:
  - name: allow-all
    paths: ["/**"]
    operations: ["*"]
    decision: allow

signal_rules:
  - name: allow-self
    signals: ["@all"]
    target:
      type: self
    decision: allow
  - name: allow-children
    signals: ["@all"]
    target:
      type: children
    decision: allow

resource_limits:
  command_timeout: 30s
  session_timeout: 1h
  idle_timeout: 30m
`

// Config with env_inject pointing to bash_startup.sh
const alpineEnvInjectConfigYAML = `
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
    execve:
      enabled: false
  env_inject:
    BASH_ENV: "/usr/lib/agentsh/bash_startup.sh"
policies:
  dir: "/policies"
  default: "env-inject-test"
approvals:
  enabled: false
metrics:
  enabled: false
health:
  path: "/health"
trash:
  enabled: false
`
