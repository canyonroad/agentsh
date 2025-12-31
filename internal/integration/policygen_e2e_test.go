//go:build integration

package integration

import (
	"context"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/internal/policygen"
	"github.com/agentsh/agentsh/pkg/types"
)

// TestPolicyGenEndToEnd tests the full policy generation flow:
// 1. Start agentsh server with permissive policy
// 2. Create session and run commands that generate events
// 3. Query events from the API
// 4. Generate a policy and verify it captures command_rules and file_rules
func TestPolicyGenEndToEnd(t *testing.T) {
	ctx := context.Background()

	bin := buildAgentshBinary(t)
	temp := t.TempDir()

	policiesDir := filepath.Join(temp, "policies")
	mustMkdir(t, policiesDir)
	// Use a permissive policy that allows everything (for profiling)
	writeFile(t, filepath.Join(policiesDir, "permissive.yaml"), permissivePolicyYAML)

	keysPath := filepath.Join(temp, "keys.yaml")
	writeFile(t, keysPath, testAPIKeysYAML)

	configPath := filepath.Join(temp, "config.yaml")
	writeFile(t, configPath, policyGenTestConfigYAML)

	workspace := filepath.Join(temp, "workspace")
	mustMkdir(t, workspace)
	writeFile(t, filepath.Join(workspace, "test.txt"), "hello world")
	writeFile(t, filepath.Join(workspace, "data.json"), `{"key": "value"}`)

	endpoint, cleanup := startServerContainer(t, ctx, bin, configPath, policiesDir, workspace)
	t.Cleanup(func() { cleanup() })

	cli := client.New(endpoint, "test-key")

	// Create session
	sess, err := cli.CreateSession(ctx, "/workspace", "permissive")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	t.Logf("Created session: %s", sess.ID)

	// --- Run various commands to generate events ---

	// 1. ls command
	t.Log("Running: ls")
	resp, err := cli.Exec(ctx, sess.ID, types.ExecRequest{
		Command: "ls",
		Args:    []string{"-la"},
	})
	if err != nil {
		t.Fatalf("Exec ls: %v", err)
	}
	if resp.Result.ExitCode != 0 {
		t.Errorf("ls should succeed, got exit %d: %s", resp.Result.ExitCode, resp.Result.Stderr)
	}

	// 2. cat command - read a file
	t.Log("Running: cat test.txt")
	resp, err = cli.Exec(ctx, sess.ID, types.ExecRequest{
		Command: "cat",
		Args:    []string{"test.txt"},
	})
	if err != nil {
		t.Fatalf("Exec cat: %v", err)
	}
	if resp.Result.ExitCode != 0 {
		t.Errorf("cat should succeed, got exit %d", resp.Result.ExitCode)
	}
	if !strings.Contains(resp.Result.Stdout, "hello world") {
		t.Errorf("cat output should contain 'hello world', got: %s", resp.Result.Stdout)
	}

	// 3. echo command
	t.Log("Running: echo")
	resp, err = cli.Exec(ctx, sess.ID, types.ExecRequest{
		Command: "echo",
		Args:    []string{"test", "output"},
	})
	if err != nil {
		t.Fatalf("Exec echo: %v", err)
	}
	if resp.Result.ExitCode != 0 {
		t.Errorf("echo should succeed, got exit %d", resp.Result.ExitCode)
	}

	// 4. head command - different way to read file
	t.Log("Running: head data.json")
	resp, err = cli.Exec(ctx, sess.ID, types.ExecRequest{
		Command: "head",
		Args:    []string{"-n", "1", "data.json"},
	})
	if err != nil {
		t.Fatalf("Exec head: %v", err)
	}
	if resp.Result.ExitCode != 0 {
		t.Errorf("head should succeed, got exit %d", resp.Result.ExitCode)
	}

	// Small delay to ensure events are flushed
	time.Sleep(500 * time.Millisecond)

	// --- Query events from the API ---
	t.Log("Querying session events")
	events, err := cli.QuerySessionEvents(ctx, sess.ID, url.Values{})
	if err != nil {
		t.Fatalf("QuerySessionEvents: %v", err)
	}
	t.Logf("Retrieved %d events", len(events))

	if len(events) == 0 {
		t.Fatal("Expected events to be captured, got none")
	}

	// Count event types for debugging
	typeCounts := make(map[string]int)
	for _, ev := range events {
		typeCounts[ev.Type]++
	}
	t.Logf("Event types: %v", typeCounts)

	// Verify we have command_started events
	if typeCounts["command_started"] == 0 {
		t.Error("Expected command_started events")
	}

	// --- Generate policy ---
	t.Log("Generating policy from events")
	store := &memEventStore{events: events}
	gen := policygen.NewGenerator(store)

	session := types.Session{
		ID:        sess.ID,
		State:     types.SessionStateRunning,
		CreatedAt: time.Now().Add(-5 * time.Minute),
		Policy:    "permissive",
		Workspace: "/workspace",
	}

	opts := policygen.DefaultOptions()
	policy, err := gen.Generate(ctx, session, opts)
	if err != nil {
		t.Fatalf("Generate policy: %v", err)
	}

	// --- Validate generated policy ---
	t.Log("Validating generated policy")

	// Should have command rules
	if len(policy.CommandRules) == 0 {
		t.Error("Expected command_rules to be generated")
	} else {
		t.Logf("Generated %d command rules", len(policy.CommandRules))
		for _, r := range policy.CommandRules {
			t.Logf("  - %s: %v", r.Name, r.Commands)
		}
	}

	// Verify specific commands are captured
	commandsFound := make(map[string]bool)
	for _, r := range policy.CommandRules {
		for _, cmd := range r.Commands {
			commandsFound[cmd] = true
		}
	}

	expectedCommands := []string{"ls", "cat", "echo", "head"}
	for _, cmd := range expectedCommands {
		if !commandsFound[cmd] {
			t.Errorf("Expected command %q in generated policy", cmd)
		}
	}

	// Should have file rules
	if len(policy.FileRules) == 0 {
		t.Error("Expected file_rules to be generated")
	} else {
		t.Logf("Generated %d file rules", len(policy.FileRules))
		for _, r := range policy.FileRules {
			t.Logf("  - %s: %v (%v)", r.Name, r.Paths, r.Operations)
		}
	}

	// --- Generate YAML and validate structure ---
	t.Log("Generating YAML output")
	yaml := policygen.FormatYAML(policy, "generated-from-e2e")

	if yaml == "" {
		t.Fatal("Empty YAML output")
	}

	// Check YAML contains expected sections
	checks := []struct {
		name    string
		content string
	}{
		{"version", "version: 1"},
		{"name", "name: generated-from-e2e"},
		{"command_rules section", "command_rules:"},
		{"file_rules section", "file_rules:"},
		{"ls command", `commands: ["ls"]`},
		{"cat command", `commands: ["cat"]`},
		{"workspace path", "/workspace"},
	}

	for _, check := range checks {
		if !strings.Contains(yaml, check.content) {
			t.Errorf("YAML missing %s (looking for %q)", check.name, check.content)
		}
	}

	t.Logf("Generated policy YAML length: %d bytes", len(yaml))

	// Cleanup
	if err := cli.DestroySession(ctx, sess.ID); err != nil {
		t.Logf("DestroySession: %v (non-fatal)", err)
	}
}

// Permissive policy that allows all operations for profiling
const permissivePolicyYAML = `
version: 1
name: permissive
description: Permissive policy for profiling sessions

file_rules:
  - name: allow-all-files
    paths: ["/**"]
    operations: ["read", "write", "create", "delete", "stat", "open", "list"]
    decision: allow

command_rules:
  - name: allow-all-commands
    decision: allow

network_rules:
  - name: allow-all-network
    domains: ["*"]
    decision: allow
`

// Config for policy generation e2e test
const policyGenTestConfigYAML = `
server:
  http:
    addr: "0.0.0.0:8080"
  unix_socket:
    enabled: false
  tls:
    enabled: false

policies:
  dir: "/app/policies"
  default: "permissive"

auth:
  api_keys:
    enabled: true
    keys_file: "/app/keys.yaml"

sandbox:
  fuse:
    enabled: true
    audit:
      enabled: true
      mode: "monitor"

storage:
  type: "sqlite"
  sqlite:
    path: "/app/data/events.db"
`
