// internal/policygen/integration_test.go
package policygen

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

func TestIntegration_FullPolicyGeneration(t *testing.T) {
	// Simulate a realistic CI/CD session
	now := time.Now()
	events := []types.Event{
		// npm install - file reads
		{Type: "file_read", Path: "/workspace/package.json", Timestamp: now, Policy: allow()},
		{Type: "file_read", Path: "/workspace/package-lock.json", Timestamp: now.Add(time.Second), Policy: allow()},

		// npm install - network
		{Type: "net_connect", Domain: "registry.npmjs.org", Timestamp: now.Add(2 * time.Second), Policy: allow(), Fields: map[string]any{"port": 443}},

		// npm install - node_modules writes (many files)
		{Type: "file_write", Path: "/workspace/node_modules/lodash/index.js", Timestamp: now.Add(3 * time.Second), Policy: allow()},
		{Type: "file_write", Path: "/workspace/node_modules/lodash/fp.js", Timestamp: now.Add(3 * time.Second), Policy: allow()},
		{Type: "file_write", Path: "/workspace/node_modules/express/index.js", Timestamp: now.Add(4 * time.Second), Policy: allow()},
		{Type: "file_write", Path: "/workspace/node_modules/express/router.js", Timestamp: now.Add(4 * time.Second), Policy: allow()},
		{Type: "file_write", Path: "/workspace/node_modules/axios/index.js", Timestamp: now.Add(5 * time.Second), Policy: allow()},
		{Type: "file_write", Path: "/workspace/node_modules/axios/core.js", Timestamp: now.Add(5 * time.Second), Policy: allow()},

		// Build - source files
		{Type: "file_read", Path: "/workspace/src/index.ts", Timestamp: now.Add(10 * time.Second), Policy: allow()},
		{Type: "file_read", Path: "/workspace/src/utils.ts", Timestamp: now.Add(10 * time.Second), Policy: allow()},
		{Type: "file_write", Path: "/workspace/dist/index.js", Timestamp: now.Add(11 * time.Second), Policy: allow()},

		// Commands - use "exec" event type which is recognized by isCommandEvent
		{Type: "exec", Timestamp: now.Add(time.Second), Policy: allow(), Fields: map[string]any{"command": "npm"}},
		{Type: "exec", Timestamp: now.Add(10 * time.Second), Policy: allow(), Fields: map[string]any{"command": "npm"}},

		// Risky command with URL - curl is in builtinRisky
		{Type: "exec", Timestamp: now.Add(15 * time.Second), Policy: allow(), Fields: map[string]any{
			"command": "curl",
			"argv":    []interface{}{"curl", "https://api.github.com/repos/test"},
		}},
		{Type: "net_connect", Domain: "api.github.com", Timestamp: now.Add(15 * time.Second), Policy: allow(), Fields: map[string]any{"port": 443, "command": "curl"}},

		// Blocked operation
		{Type: "file_write", Path: "/etc/hosts", Timestamp: now.Add(20 * time.Second), Policy: deny("system file")},
	}

	store := &mockEventStore{events: events}
	gen := NewGenerator(store)

	sess := types.Session{ID: "integration-test-session"}
	opts := DefaultOptions()
	opts.Threshold = 3 // Low for testing

	policy, err := gen.Generate(context.Background(), sess, opts)
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}

	// Verify structure
	if policy.SessionID != "integration-test-session" {
		t.Errorf("wrong session ID: %s", policy.SessionID)
	}

	// Should have file rules
	if len(policy.FileRules) == 0 {
		t.Error("expected file rules")
	}

	// Should collapse node_modules
	hasNodeModulesGlob := false
	for _, r := range policy.FileRules {
		if strings.Contains(r.Paths[0], "node_modules/**") {
			hasNodeModulesGlob = true
			break
		}
	}
	if !hasNodeModulesGlob {
		t.Error("expected node_modules to be collapsed to glob")
	}

	// Should have network rules
	if len(policy.NetworkRules) == 0 {
		t.Error("expected network rules")
	}

	// Should have command rules
	if len(policy.CommandRules) == 0 {
		t.Error("expected command rules")
	}

	// curl should be marked as risky with arg pattern
	var curlRule *CommandRuleGen
	for i := range policy.CommandRules {
		if len(policy.CommandRules[i].Commands) > 0 && policy.CommandRules[i].Commands[0] == "curl" {
			curlRule = &policy.CommandRules[i]
			break
		}
	}
	if curlRule == nil {
		t.Error("expected curl command rule")
	} else {
		if !curlRule.Risky {
			t.Error("curl should be marked risky")
		}
		if curlRule.ArgsPattern == "" {
			t.Error("curl should have arg pattern")
		}
	}

	// Should have blocked files
	if len(policy.BlockedFiles) == 0 {
		t.Error("expected blocked file rules")
	}

	// Format as YAML and verify
	yaml := FormatYAML(policy, "ci-build")

	if !strings.Contains(yaml, "version: 1") {
		t.Error("missing version in YAML")
	}
	if !strings.Contains(yaml, "name: ci-build") {
		t.Error("missing name in YAML")
	}
	if !strings.Contains(yaml, "# BLOCKED:") {
		t.Error("missing blocked section in YAML")
	}
	if !strings.Contains(yaml, "# RISKY:") {
		t.Error("missing risky indicator in YAML")
	}
}

func TestIntegration_MCPPolicyGeneration(t *testing.T) {
	now := time.Now()
	events := []types.Event{
		// File event (existing behavior)
		{Type: "file_read", Path: "/workspace/main.go", Timestamp: now,
			Policy: &types.PolicyInfo{Decision: types.DecisionAllow}},
		// MCP events
		{ID: "m1", Type: "mcp_tool_seen", Timestamp: now.Add(time.Second), Fields: map[string]any{
			"server_id": "gh", "tool_name": "create_pr",
			"tool_hash": "sha256:pr123", "server_type": "stdio",
		}},
		{ID: "m2", Type: "mcp_tool_called", Timestamp: now.Add(2 * time.Second), Fields: map[string]any{
			"server_id": "gh", "tool_name": "create_pr",
		}},
	}

	store := &mockEventStore{events: events}
	gen := NewGenerator(store)

	sess := types.Session{ID: "integration-test"}
	policy, err := gen.Generate(context.Background(), sess, DefaultOptions())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Should have both file rules AND MCP rules
	if len(policy.FileRules) == 0 {
		t.Error("expected file rules")
	}
	if len(policy.MCPToolRules) == 0 {
		t.Error("expected MCP tool rules")
	}

	// Format YAML and verify both sections present
	yaml := FormatYAML(policy, "integration-test")
	if !strings.Contains(yaml, "file_rules:") {
		t.Error("YAML missing file_rules section")
	}
	if !strings.Contains(yaml, "mcp_rules:") {
		t.Error("YAML missing mcp_rules section")
	}
	if !strings.Contains(yaml, `tool: "create_pr"`) {
		t.Error("YAML missing MCP tool")
	}
	if !strings.Contains(yaml, `content_hash: "sha256:pr123"`) {
		t.Error("YAML missing content hash")
	}
}

func allow() *types.PolicyInfo {
	return &types.PolicyInfo{Decision: types.DecisionAllow}
}

func deny(msg string) *types.PolicyInfo {
	return &types.PolicyInfo{Decision: types.DecisionDeny, Message: msg}
}
