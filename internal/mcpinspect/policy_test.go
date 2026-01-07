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
