//go:build integration

package integration

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/internal/report"
	"github.com/agentsh/agentsh/pkg/types"
)

// TestReportEndToEnd tests the full flow:
// 1. Start agentsh server in container with mixed policy (allow/deny/redirect)
// 2. Create session and run commands that trigger different decisions
// 3. Query events from the API
// 4. Generate a report and verify it reflects actual activity
func TestReportEndToEnd(t *testing.T) {
	ctx := context.Background()

	bin := buildAgentshBinary(t)
	temp := t.TempDir()

	policiesDir := filepath.Join(temp, "policies")
	mustMkdir(t, policiesDir)
	writeFile(t, filepath.Join(policiesDir, "e2e-test.yaml"), e2eTestPolicyYAML)

	keysPath := filepath.Join(temp, "keys.yaml")
	writeFile(t, keysPath, testAPIKeysYAML)

	// Enable audit storage for event capture
	configPath := filepath.Join(temp, "config.yaml")
	writeFile(t, configPath, e2eTestConfigYAML)

	workspace := filepath.Join(temp, "workspace")
	mustMkdir(t, workspace)
	writeFile(t, filepath.Join(workspace, "test.txt"), "hello world")
	writeFile(t, filepath.Join(workspace, "secret.env"), "API_KEY=secret123")

	endpoint, cleanup := startServerContainer(t, ctx, bin, configPath, policiesDir, workspace)
	t.Cleanup(func() { cleanup() })

	cli := client.New(endpoint, "test-key")

	// Create session
	sess, err := cli.CreateSession(ctx, "/workspace", "e2e-test")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	t.Logf("Created session: %s", sess.ID)

	// --- Run commands that trigger different policy decisions ---

	// 1. ALLOW: echo command
	t.Log("Running allowed command: echo")
	resp, err := cli.Exec(ctx, sess.ID, types.ExecRequest{
		Command: "echo",
		Args:    []string{"hello", "from", "test"},
	})
	if err != nil {
		t.Fatalf("Exec echo: %v", err)
	}
	if resp.Result.ExitCode != 0 {
		t.Errorf("echo should succeed, got exit %d", resp.Result.ExitCode)
	}

	// 2. ALLOW: ls command
	t.Log("Running allowed command: ls")
	resp, err = cli.Exec(ctx, sess.ID, types.ExecRequest{
		Command: "ls",
		Args:    []string{"-la", "/workspace"},
	})
	if err != nil {
		t.Fatalf("Exec ls: %v", err)
	}
	if resp.Result.ExitCode != 0 {
		t.Errorf("ls should succeed, got exit %d", resp.Result.ExitCode)
	}

	// 3. ALLOW: cat workspace file
	t.Log("Running allowed command: cat workspace file")
	resp, err = cli.Exec(ctx, sess.ID, types.ExecRequest{
		Command: "cat",
		Args:    []string{"/workspace/test.txt"},
	})
	if err != nil {
		t.Fatalf("Exec cat: %v", err)
	}
	if resp.Result.ExitCode != 0 {
		t.Errorf("cat workspace file should succeed, got exit %d", resp.Result.ExitCode)
	}

	// 4. DENY: cat /etc/passwd (blocked by policy)
	t.Log("Running denied command: cat /etc/passwd")
	_, err = cli.Exec(ctx, sess.ID, types.ExecRequest{
		Command: "cat",
		Args:    []string{"/etc/passwd"},
	})
	var httpErr *client.HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusForbidden {
		t.Errorf("cat /etc/passwd should be denied with 403, got: %v", err)
	}

	// 5. DENY: nc (network tool blocked)
	t.Log("Running denied command: nc")
	_, err = cli.Exec(ctx, sess.ID, types.ExecRequest{
		Command: "nc",
		Args:    []string{"-h"},
	})
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusForbidden {
		t.Errorf("nc should be denied with 403, got: %v", err)
	}

	// 6. DENY: rm -rf (recursive delete blocked)
	t.Log("Running denied command: rm -rf")
	_, err = cli.Exec(ctx, sess.ID, types.ExecRequest{
		Command: "rm",
		Args:    []string{"-rf", "/workspace"},
	})
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusForbidden {
		t.Errorf("rm -rf should be denied with 403, got: %v", err)
	}

	// 7. Another ALLOW for variety: pwd
	t.Log("Running allowed command: pwd")
	resp, err = cli.Exec(ctx, sess.ID, types.ExecRequest{
		Command: "pwd",
	})
	if err != nil {
		t.Fatalf("Exec pwd: %v", err)
	}
	if resp.Result.ExitCode != 0 {
		t.Errorf("pwd should succeed, got exit %d", resp.Result.ExitCode)
	}

	// Give the server a moment to flush events
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

	// --- Generate report ---
	t.Log("Generating report")
	store := &memEventStore{events: events}
	gen := report.NewGenerator(store)

	session := types.Session{
		ID:        sess.ID,
		State:     types.SessionStateRunning,
		CreatedAt: time.Now().Add(-5 * time.Minute),
		Policy:    "e2e-test",
		Workspace: "/workspace",
	}

	rpt, err := gen.Generate(ctx, session, report.LevelDetailed)
	if err != nil {
		t.Fatalf("Generate report: %v", err)
	}

	// --- Validate report content ---
	t.Log("Validating report content")

	// Should have allowed operations
	if rpt.Decisions.Allowed == 0 {
		t.Error("Expected some allowed operations")
	}
	t.Logf("Allowed: %d, Blocked: %d, Redirected: %d",
		rpt.Decisions.Allowed, rpt.Decisions.Blocked, rpt.Decisions.Redirected)

	// Should have blocked operations (we tried cat /etc/passwd, nc, rm -rf)
	if rpt.Decisions.Blocked == 0 {
		t.Error("Expected some blocked operations from denied commands")
	}

	// Should have findings for blocked operations
	hasBlockedFinding := false
	for _, f := range rpt.Findings {
		if f.Category == "blocked" && f.Severity == report.SeverityCritical {
			hasBlockedFinding = true
			t.Logf("Found blocked finding: %s (count: %d)", f.Title, f.Count)
		}
	}
	if !hasBlockedFinding {
		t.Error("Expected a critical finding for blocked operations")
	}

	// Should have activity data
	if rpt.Activity.Commands == 0 {
		t.Error("Expected command activity to be recorded")
	}
	t.Logf("Activity - Commands: %d, FileOps: %d, NetworkOps: %d",
		rpt.Activity.Commands, rpt.Activity.FileOps, rpt.Activity.NetworkOps)

	// --- Generate markdown and validate structure ---
	t.Log("Generating markdown output")
	md := report.FormatMarkdown(rpt)

	if md == "" {
		t.Fatal("Empty markdown output")
	}

	// Check markdown contains expected sections
	checks := []struct {
		name    string
		content string
	}{
		{"header", "Session Report:"},
		{"overview section", "## Overview"},
		{"decision summary", "## Decision Summary"},
		{"allowed count", "Allowed"},
		{"blocked count", "Blocked"},
		{"findings section", "## Findings"},
		{"blocked finding", "[CRITICAL]"},
		{"blocked operations table", "## Blocked Operations"},
	}

	for _, check := range checks {
		if !strings.Contains(md, check.content) {
			t.Errorf("Markdown missing %s (looking for %q)", check.name, check.content)
		}
	}

	t.Logf("Report markdown length: %d bytes", len(md))

	// Cleanup
	if err := cli.DestroySession(ctx, sess.ID); err != nil {
		t.Logf("DestroySession: %v (non-fatal)", err)
	}

	t.Log("End-to-end report test passed!")
}

// memEventStore is a simple in-memory store for the generator
type memEventStore struct {
	events []types.Event
}

func (m *memEventStore) QueryEvents(ctx context.Context, q types.EventQuery) ([]types.Event, error) {
	return m.events, nil
}

func (m *memEventStore) AppendEvent(ctx context.Context, ev types.Event) error {
	return nil
}

func (m *memEventStore) Close() error {
	return nil
}

// e2eTestPolicyYAML defines a policy with allow, deny, and redirect rules
const e2eTestPolicyYAML = `
version: 1
name: e2e-test
description: End-to-end test policy with mixed decisions

file_rules:
  - name: allow-workspace
    description: Allow workspace access
    paths:
      - "/workspace/**"
    operations:
      - "*"
    decision: allow

  - name: allow-tmp
    description: Allow temp access
    paths:
      - "/tmp/**"
    operations:
      - "*"
    decision: allow

  - name: deny-etc
    description: Block /etc access
    paths:
      - "/etc/**"
    operations:
      - "*"
    decision: deny
    message: "Access to /etc is blocked"

  - name: deny-proc-sys
    description: Block /proc and /sys
    paths:
      - "/proc/**"
      - "/sys/**"
    operations:
      - "*"
    decision: deny

  - name: allow-system-read
    description: Read system paths
    paths:
      - "/usr/**"
      - "/lib/**"
      - "/lib64/**"
      - "/bin/**"
      - "/sbin/**"
    operations:
      - read
      - open
      - stat
      - list
    decision: allow

  - name: default-deny
    description: Deny everything else
    paths:
      - "**"
    operations:
      - "*"
    decision: deny

command_rules:
  - name: allow-safe-commands
    description: Safe commands
    commands:
      - echo
      - ls
      - cat
      - pwd
      - head
      - tail
      - grep
      - wc
    decision: allow

  - name: deny-network-tools
    description: Block network tools
    commands:
      - nc
      - netcat
      - ncat
      - telnet
      - ssh
      - curl
      - wget
    decision: deny
    message: "Network tool blocked"

  - name: deny-rm-recursive
    description: Block recursive delete
    commands:
      - rm
    args_patterns:
      - "*-r*"
      - "*--recursive*"
    decision: deny
    message: "Recursive delete blocked"

  - name: allow-rm-single
    description: Allow single file rm
    commands:
      - rm
    decision: allow

resource_limits:
  max_memory_mb: 512
  cpu_quota_percent: 50
  pids_max: 50
  command_timeout: 30s
  session_timeout: 10m
  idle_timeout: 5m
`

// e2eTestConfigYAML enables audit storage for event capture
const e2eTestConfigYAML = `
server:
  http:
    addr: "0.0.0.0:8080"
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
  base_dir: "/sessions"
sandbox:
  fuse:
    enabled: false
  network:
    enabled: false
policies:
  dir: "/policies"
  default: "e2e-test"
approvals:
  enabled: false
metrics:
  enabled: false
health:
  path: "/health"
`
