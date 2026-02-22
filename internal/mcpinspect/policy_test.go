package mcpinspect

import (
	"testing"

	"github.com/agentsh/agentsh/internal/config"
)

func TestPolicyEvaluator_AllowlistMode(t *testing.T) {
	cfg := config.SandboxMCPConfig{
		EnforcePolicy: true,
		ToolPolicy:    "allowlist",
		AllowedTools: []config.MCPToolRule{
			{Server: "filesystem", Tool: "read_file"},
			{Server: "github", Tool: "*"},
		},
	}

	eval := NewPolicyEvaluator(cfg)

	tests := []struct {
		server   string
		tool     string
		expected bool
	}{
		{"filesystem", "read_file", true},
		{"filesystem", "write_file", false},
		{"github", "create_issue", true},
		{"github", "any_tool", true},
		{"unknown", "any", false},
	}

	for _, tc := range tests {
		result := eval.IsAllowed(tc.server, tc.tool)
		if result != tc.expected {
			t.Errorf("IsAllowed(%q, %q) = %v, want %v", tc.server, tc.tool, result, tc.expected)
		}
	}
}

func TestPolicyEvaluator_DenylistMode(t *testing.T) {
	cfg := config.SandboxMCPConfig{
		EnforcePolicy: true,
		ToolPolicy:    "denylist",
		DeniedTools: []config.MCPToolRule{
			{Server: "*", Tool: "execute_shell"},
			{Server: "dangerous", Tool: "*"},
		},
	}

	eval := NewPolicyEvaluator(cfg)

	tests := []struct {
		server   string
		tool     string
		expected bool
	}{
		{"filesystem", "execute_shell", false},
		{"github", "execute_shell", false},
		{"dangerous", "any_tool", false},
		{"filesystem", "read_file", true},
		{"github", "create_issue", true},
	}

	for _, tc := range tests {
		result := eval.IsAllowed(tc.server, tc.tool)
		if result != tc.expected {
			t.Errorf("IsAllowed(%q, %q) = %v, want %v", tc.server, tc.tool, result, tc.expected)
		}
	}
}

func TestPolicyEvaluator_HashVerification(t *testing.T) {
	cfg := config.SandboxMCPConfig{
		EnforcePolicy: true,
		ToolPolicy:    "allowlist",
		AllowedTools: []config.MCPToolRule{
			{Server: "custom", Tool: "query_db", ContentHash: "sha256:abc123"},
		},
	}

	eval := NewPolicyEvaluator(cfg)

	if eval.IsAllowedWithHash("custom", "query_db", "sha256:abc123") != true {
		t.Error("Expected allowed with matching hash")
	}
	if eval.IsAllowedWithHash("custom", "query_db", "sha256:different") != false {
		t.Error("Expected denied with different hash")
	}
}

func TestPolicyEvaluator_ServerAllowlist(t *testing.T) {
	cfg := config.SandboxMCPConfig{
		EnforcePolicy: true,
		ServerPolicy:  "allowlist",
		AllowedServers: []config.MCPServerRule{
			{ID: "filesystem"},
			{ID: "github"},
		},
		ToolPolicy: "denylist", // no denied tools — all tools allowed if server passes
	}

	eval := NewPolicyEvaluator(cfg)

	tests := []struct {
		name     string
		server   string
		tool     string
		expected bool
		reason   string
	}{
		{"allowed server", "filesystem", "read_file", true, ""},
		{"allowed server any tool", "github", "create_issue", true, ""},
		{"blocked server", "unknown-server", "any_tool", false, "server not in allowlist"},
		{"blocked server case insensitive", "FILESYSTEM", "read_file", true, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			decision := eval.Evaluate(tc.server, tc.tool, "")
			if decision.Allowed != tc.expected {
				t.Errorf("Evaluate(%q, %q) allowed=%v, want %v (reason: %s)",
					tc.server, tc.tool, decision.Allowed, tc.expected, decision.Reason)
			}
			if tc.reason != "" && decision.Reason != tc.reason {
				t.Errorf("Evaluate(%q, %q) reason=%q, want %q",
					tc.server, tc.tool, decision.Reason, tc.reason)
			}
		})
	}
}

func TestPolicyEvaluator_ServerDenylist(t *testing.T) {
	cfg := config.SandboxMCPConfig{
		EnforcePolicy: true,
		ServerPolicy:  "denylist",
		DeniedServers: []config.MCPServerRule{
			{ID: "untrusted-server"},
			{ID: "risky-server"},
		},
	}

	eval := NewPolicyEvaluator(cfg)

	tests := []struct {
		name     string
		server   string
		tool     string
		expected bool
	}{
		{"denied server", "untrusted-server", "any_tool", false},
		{"denied server 2", "risky-server", "read_file", false},
		{"allowed server", "filesystem", "read_file", true},
		{"allowed server 2", "github", "create_issue", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			decision := eval.Evaluate(tc.server, tc.tool, "")
			if decision.Allowed != tc.expected {
				t.Errorf("Evaluate(%q, %q) allowed=%v, want %v (reason: %s)",
					tc.server, tc.tool, decision.Allowed, tc.expected, decision.Reason)
			}
		})
	}
}

func TestPolicyEvaluator_ServerPolicyBeforeToolPolicy(t *testing.T) {
	// Server is denied, but tool would be allowed — server should win
	cfg := config.SandboxMCPConfig{
		EnforcePolicy: true,
		ServerPolicy:  "denylist",
		DeniedServers: []config.MCPServerRule{
			{ID: "blocked-server"},
		},
		ToolPolicy: "allowlist",
		AllowedTools: []config.MCPToolRule{
			{Server: "*", Tool: "*"}, // allow all tools
		},
	}

	eval := NewPolicyEvaluator(cfg)

	decision := eval.Evaluate("blocked-server", "read_file", "")
	if decision.Allowed {
		t.Error("Expected blocked — server denylist should run before tool allowlist")
	}
	if decision.Reason != "server in denylist" {
		t.Errorf("Expected reason 'server in denylist', got %q", decision.Reason)
	}
}

func TestPolicyEvaluator_ServerAllowlistWithToolDenylist(t *testing.T) {
	// Org approves certain servers, but denies specific dangerous tools
	cfg := config.SandboxMCPConfig{
		EnforcePolicy: true,
		ServerPolicy:  "allowlist",
		AllowedServers: []config.MCPServerRule{
			{ID: "filesystem"},
			{ID: "github"},
		},
		ToolPolicy: "denylist",
		DeniedTools: []config.MCPToolRule{
			{Server: "*", Tool: "execute_command"},
		},
	}

	eval := NewPolicyEvaluator(cfg)

	tests := []struct {
		name     string
		server   string
		tool     string
		expected bool
	}{
		{"approved server, safe tool", "filesystem", "read_file", true},
		{"approved server, dangerous tool", "filesystem", "execute_command", false},
		{"unapproved server", "unknown", "read_file", false},
		{"unapproved server, any tool", "rogue-mcp", "safe_tool", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			decision := eval.Evaluate(tc.server, tc.tool, "")
			if decision.Allowed != tc.expected {
				t.Errorf("Evaluate(%q, %q) allowed=%v, want %v (reason: %s)",
					tc.server, tc.tool, decision.Allowed, tc.expected, decision.Reason)
			}
		})
	}
}

func TestPolicyEvaluator_ServerWildcardDeny(t *testing.T) {
	// Deny all servers (lockdown mode), allow specific ones
	cfg := config.SandboxMCPConfig{
		EnforcePolicy: true,
		ServerPolicy:  "allowlist",
		AllowedServers: []config.MCPServerRule{
			{ID: "filesystem"},
		},
	}

	eval := NewPolicyEvaluator(cfg)

	// Only filesystem should be allowed
	d1 := eval.Evaluate("filesystem", "read_file", "")
	if !d1.Allowed {
		t.Error("Expected filesystem to be allowed")
	}

	d2 := eval.Evaluate("anything-else", "any_tool", "")
	if d2.Allowed {
		t.Error("Expected non-filesystem server to be blocked")
	}
}

func TestPolicyEvaluator_NoServerPolicySkipsToToolPolicy(t *testing.T) {
	// No server_policy set — should fall through to tool policy
	cfg := config.SandboxMCPConfig{
		EnforcePolicy: true,
		// ServerPolicy not set (empty string)
		ToolPolicy: "allowlist",
		AllowedTools: []config.MCPToolRule{
			{Server: "filesystem", Tool: "read_file"},
		},
	}

	eval := NewPolicyEvaluator(cfg)

	d1 := eval.Evaluate("filesystem", "read_file", "")
	if !d1.Allowed {
		t.Error("Expected allowed — no server policy, tool matches allowlist")
	}

	d2 := eval.Evaluate("filesystem", "write_file", "")
	if d2.Allowed {
		t.Error("Expected blocked — tool not in allowlist")
	}
}
