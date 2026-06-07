//go:build integration && linux

package integration

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/testcontainers/testcontainers-go"
)

// TestExecPath_WrapperLogRoutedOffCommandStderr is the end-to-end
// acceptance test for issue #415: a wrapped command's stderr must not
// carry the per-exec "seccomp: filter loaded" wrapper diagnostic, and
// that diagnostic must instead appear in the server log (drained from
// the wrapper log pipe) at the default level.
func TestExecPath_WrapperLogRoutedOffCommandStderr(t *testing.T) {
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

	// Probe exec: confirm seccomp-user-notify is operational in this
	// environment before asserting anything about log routing.
	// Mirror the same probe-skip pattern as TestWrapStrongMode_SetsInSessionMarker.
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

	// Main session: run a command that writes to stderr so we can verify
	// the wrapper diagnostic is NOT mixed into it.
	sess, err := cli.CreateSession(ctx, "/workspace", "agent-default")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	t.Cleanup(func() {
		if err := cli.DestroySession(context.Background(), sess.ID); err != nil {
			t.Logf("DestroySession: %v", err)
		}
	})

	execCtx, execCancel := context.WithTimeout(ctx, 30*time.Second)
	res, execErr := cli.Exec(execCtx, sess.ID, types.ExecRequest{
		Command: "/bin/sh",
		Args:    []string{"-c", "echo STDERR_MARKER >&2"},
	})
	execCancel()
	if execErr != nil {
		if errors.Is(execErr, context.DeadlineExceeded) || strings.Contains(execErr.Error(), "deadline exceeded") {
			t.Skip("seccomp-user-notify appears unreliable in this environment (exec timeout)")
		}
		t.Fatalf("Exec: %v", execErr)
	}
	if res.Result.ExitCode != 0 {
		t.Skipf("seccomp-user-notify may not be active in this environment (exit=%d, stderr=%q)", res.Result.ExitCode, res.Result.Stderr)
	}

	// (a) The command's own stderr arrives intact and uncontaminated.
	if !strings.Contains(res.Result.Stderr, "STDERR_MARKER") {
		t.Fatalf("command stderr lost: %q", res.Result.Stderr)
	}
	if strings.Contains(res.Result.Stderr, "seccomp: filter loaded") {
		t.Fatalf("wrapper diagnostic leaked onto command stderr (issue #415 regression):\n%s", res.Result.Stderr)
	}

	// (b) The diagnostic lands in the server log at default level
	// (logging.level=info in the test config). The drain goroutine is
	// asynchronous to the Exec response (fire-and-forget in
	// startWrapperHandlers) and Docker's log driver adds its own
	// propagation delay, so poll rather than read once.
	logsCtx, logsCancel := context.WithTimeout(ctx, 30*time.Second)
	defer logsCancel()
	var serverLog string
	for {
		serverLog = readContainerLogs(t, logsCtx, ctr)
		if strings.Contains(serverLog, "seccomp: filter loaded") && strings.Contains(serverLog, "wait_killable") {
			break
		}
		select {
		case <-logsCtx.Done():
			// fall through to the assertions below with the last read,
			// so the failure message carries the full server log.
		case <-time.After(500 * time.Millisecond):
			continue
		}
		break
	}
	if !strings.Contains(serverLog, "seccomp: filter loaded") {
		t.Fatalf("wrapper diagnostic missing from server log (acceptance criterion #2)\nserver log:\n%s", serverLog)
	}
	if !strings.Contains(serverLog, "wait_killable") {
		t.Fatalf("wait_killable field missing from drained diagnostic\nserver log:\n%s", serverLog)
	}
}

// readContainerLogs returns the container's full log history; Logs
// streams from the start on every call, so each poll sees everything.
func readContainerLogs(t *testing.T, ctx context.Context, ctr testcontainers.Container) string {
	t.Helper()
	reader, err := ctr.Logs(ctx)
	if err != nil {
		t.Fatalf("container logs: %v", err)
	}
	defer reader.Close()
	b, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read container logs: %v", err)
	}
	return string(b)
}
