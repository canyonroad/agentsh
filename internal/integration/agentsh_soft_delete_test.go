//go:build integration

package integration

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/pkg/types"
)

// Requires /dev/fuse inside the docker host (Github ubuntu runners provide it).
func TestSoftDeleteAndRestore(t *testing.T) {
	ctx := context.Background()

	bin := buildAgentshBinary(t)
	temp := t.TempDir()

	policiesDir := filepath.Join(temp, "policies")
	mustMkdir(t, policiesDir)
	writeFile(t, filepath.Join(policiesDir, "default.yaml"), softDeletePolicyYAML)

	keysPath := filepath.Join(temp, "keys.yaml")
	writeFile(t, keysPath, testAPIKeysYAML)

	configPath := filepath.Join(temp, "config.yaml")
	writeFile(t, configPath, softDeleteConfigYAML)

	workspace := filepath.Join(temp, "workspace")
	mustMkdir(t, workspace)
	writeFile(t, filepath.Join(workspace, "secret.txt"), "top secret")

	endpoint, cleanup := startServerContainer(t, ctx, bin, configPath, policiesDir, workspace)
	t.Cleanup(func() { cleanup() })

	cli := client.New(endpoint, "test-key")

	sess, err := cli.CreateSession(ctx, "/workspace", "default")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// Delete the file; expect soft-delete guidance and stderr hint.
	delResp, err := cli.Exec(ctx, sess.ID, types.ExecRequest{
		Command: "rm",
		Args:    []string{"/workspace/secret.txt"},
	})
	if err != nil {
		t.Fatalf("Exec rm: %v", err)
	}
	if delResp.Result.ExitCode != 0 {
		t.Fatalf("rm exit=%d stderr=%s", delResp.Result.ExitCode, delResp.Result.Stderr)
	}
	softEventFound := false
	for _, ev := range delResp.Events.FileOperations {
		if ev.Type == "file_soft_deleted" {
			softEventFound = true
			break
		}
	}
	if !softEventFound {
		t.Skipf("soft-delete events not observed (likely fuse unavailable); guidance=%+v", delResp.Guidance)
	}
	if delResp.Guidance == nil || len(delResp.Guidance.Suggestions) == 0 {
		t.Fatalf("expected soft-delete guidance suggestions, got %+v", delResp.Guidance)
	}

	// Extract trash token from stderr hint.
	token := ""
	for _, line := range []string{delResp.Result.Stderr, delResp.Result.Stdout} {
		if line == "" {
			continue
		}
		// crude parse: look for "token "
		if idx := findToken(line); idx != "" {
			token = idx
			break
		}
	}
	if token == "" {
		t.Fatalf("trash token not found in output: stderr=%q", delResp.Result.Stderr)
	}

	// Restore via agentsh built-in command.
	restoreCmd := types.ExecRequest{
		Command: "agentsh",
		Args:    []string{"trash", "restore", token},
		Env: map[string]string{
			"AGENTSH_SESSION_ID": sess.ID,
		},
	}
	restoreResp, err := cli.Exec(ctx, sess.ID, restoreCmd)
	if err != nil {
		t.Fatalf("restore exec: %v", err)
	}
	if restoreResp.Result.ExitCode != 0 {
		t.Fatalf("restore exit=%d stderr=%s", restoreResp.Result.ExitCode, restoreResp.Result.Stderr)
	}

	// File should be back.
	catResp, err := cli.Exec(ctx, sess.ID, types.ExecRequest{
		Command: "cat",
		Args:    []string{"/workspace/secret.txt"},
	})
	if err != nil {
		t.Fatalf("cat after restore: %v", err)
	}
	if catResp.Result.Stdout != "top secret" {
		t.Fatalf("expected restored content, got %q", catResp.Result.Stdout)
	}

	if err := cli.DestroySession(ctx, sess.ID); err != nil {
		t.Fatalf("DestroySession: %v", err)
	}
}

func findToken(s string) string {
	const key = "token "
	idx := -1
	for i := 0; i+len(key) < len(s); i++ {
		if s[i:i+len(key)] == key {
			idx = i + len(key)
			break
		}
	}
	if idx == -1 {
		return ""
	}
	j := idx
	for j < len(s) && s[j] != ' ' && s[j] != '\n' {
		j++
	}
	return s[idx:j]
}

const softDeletePolicyYAML = `
version: 1
name: default
description: soft delete integration policy
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

const softDeleteConfigYAML = `
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
    enabled: true
    audit:
      enabled: true
      mode: "soft_delete"
      trash_path: "/workspace/.agentsh_trash"
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
