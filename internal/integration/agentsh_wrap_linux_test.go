//go:build integration && linux

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
		`timeout 20s env AGENTSH_NO_AUTO=1 AGENTSH_API_KEY=test-key /usr/local/bin/agentsh --server http://127.0.0.1:18080 wrap -- /bin/sh -c 'if [ -n "$AGENTSH_IN_SESSION" ]; then echo MARKER_SET; else echo MARKER_UNSET; fi' 2>&1`,
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
	if !strings.Contains(logOutput, "MARKER_SET") {
		t.Fatalf("expected MARKER_SET in strong wrap output, got:\n%s", logOutput)
	}
	if strings.Contains(logOutput, "MARKER_UNSET") {
		t.Fatalf("did not expect MARKER_UNSET in strong wrap output, got:\n%s", logOutput)
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
