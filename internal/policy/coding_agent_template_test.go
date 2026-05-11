package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCodingAgentTemplate_Loads verifies the policy that the Docker Sandboxes
// mixin kit bakes into /etc/agentsh/policies/default.yaml parses cleanly
// through the canonical loader. Any field-name typo or schema drift will be
// caught here before the kit ships.
func TestCodingAgentTemplate_Loads(t *testing.T) {
	path := filepath.Join("..", "..", "configs", "policies", "coding-agent.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read template: %v", err)
	}
	p, err := LoadFromBytes(data)
	if err != nil {
		t.Fatalf("load template: %v", err)
	}
	if p.Name != "coding-agent" {
		t.Errorf("Name = %q, want %q", p.Name, "coding-agent")
	}
	if len(p.FileRules) == 0 {
		t.Error("expected file_rules")
	}
	if len(p.CommandRules) == 0 {
		t.Error("expected command_rules")
	}
	if len(p.SignalRules) == 0 {
		t.Error("expected signal_rules")
	}
}

// TestCodingAgentTemplate_DeniesCredentialPaths spot-checks that the rules from
// the design spec are actually present. Coverage isn't exhaustive; this just
// catches accidental rule deletion during future edits.
func TestCodingAgentTemplate_DeniesCredentialPaths(t *testing.T) {
	path := filepath.Join("..", "..", "configs", "policies", "coding-agent.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read template: %v", err)
	}
	body := string(data)
	for _, want := range []string{
		"/.ssh/",
		"/.aws/",
		"/.gnupg/",
		"/.kube/",
		"/.netrc",
		"/etc/agentsh/",
		"/usr/lib/agentsh/",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("expected coding-agent.yaml to reference %q", want)
		}
	}
}
