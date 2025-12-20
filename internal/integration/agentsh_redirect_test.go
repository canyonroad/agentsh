//go:build integration

package integration

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/pkg/types"
)

func TestCommandRedirectExecutesTargetAndLogsEvent(t *testing.T) {
	ctx := context.Background()

	bin := buildAgentshBinary(t)
	temp := t.TempDir()

	policiesDir := filepath.Join(temp, "policies")
	mustMkdir(t, policiesDir)
	writeFile(t, filepath.Join(policiesDir, "default.yaml"), redirectPolicyYAML)

	keysPath := filepath.Join(temp, "keys.yaml")
	writeFile(t, keysPath, testAPIKeysYAML)

	configPath := filepath.Join(temp, "config.yaml")
	writeFile(t, configPath, testConfigTemplate)

	workspace := filepath.Join(temp, "workspace")
	mustMkdir(t, workspace)

	endpoint, cleanup := startServerContainer(t, ctx, bin, configPath, policiesDir, workspace)
	t.Cleanup(func() { cleanup() })

	cli := client.New(endpoint, "test-key")

	sess, err := cli.CreateSession(ctx, "/workspace", "default")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	resp, err := cli.Exec(ctx, sess.ID, types.ExecRequest{
		Command: "ls",
		Args:    []string{"/workspace"},
	})
	if err != nil {
		t.Fatalf("Exec redirect: %v", err)
	}
	if resp.Result.ExitCode != 0 || resp.Result.Stdout != "redirected\n" {
		t.Fatalf("redirect result unexpected: %+v", resp.Result)
	}

	// Guidance should mention redirect.
	if resp.Guidance == nil || len(resp.Guidance.Substitutions) == 0 {
		t.Fatalf("expected redirect guidance substitutions, got %+v", resp.Guidance)
	}
	if resp.Guidance.PolicyRule != "redirect-ls" {
		t.Fatalf("expected guidance policy rule redirect-ls, got %s", resp.Guidance.PolicyRule)
	}

	// Events should include command_redirected.
	foundRedirectEvent := false
	for _, ev := range resp.Events.Other {
		if ev.Type == "command_redirected" {
			foundRedirectEvent = true
			if ev.Policy == nil || ev.Policy.Decision != types.DecisionRedirect {
				t.Fatalf("redirect event missing policy info: %+v", ev.Policy)
			}
			break
		}
	}
	if !foundRedirectEvent {
		t.Fatalf("expected command_redirected event, got %+v", resp.Events.Other)
	}

	if err := cli.DestroySession(ctx, sess.ID); err != nil {
		t.Fatalf("DestroySession: %v", err)
	}
}

const redirectPolicyYAML = `
version: 1
name: default
description: redirect integration test policy
command_rules:
  - name: redirect-ls
    commands: ["ls"]
    decision: redirect
    message: "ls redirected"
    redirect_to:
      command: "echo"
      args: ["redirected"]
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
