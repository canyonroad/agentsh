package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestPolicy_RegistryRules(t *testing.T) {
	yamlData := `
version: 1
name: test-registry
registry_rules:
  - name: block-run-keys
    paths:
      - "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
    operations:
      - write
      - create
    decision: deny
    priority: 100
    cache_ttl: 30s
`
	var p Policy
	if err := yaml.Unmarshal([]byte(yamlData), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(p.RegistryRules) != 1 {
		t.Fatalf("expected 1 registry rule, got %d", len(p.RegistryRules))
	}
	r := p.RegistryRules[0]
	if r.Name != "block-run-keys" {
		t.Errorf("name = %q, want block-run-keys", r.Name)
	}
	if r.Priority != 100 {
		t.Errorf("priority = %d, want 100", r.Priority)
	}
}

func TestSignalRuleParsing(t *testing.T) {
	yamlData := `
version: 1
name: test
signal_rules:
  - name: block-external-kill
    signals: ["@fatal", "SIGKILL"]
    target:
      type: external
    decision: deny
    fallback: audit
`
	var p Policy
	err := yaml.Unmarshal([]byte(yamlData), &p)
	require.NoError(t, err)
	require.Len(t, p.SignalRules, 1)
	assert.Equal(t, "block-external-kill", p.SignalRules[0].Name)
	assert.Equal(t, []string{"@fatal", "SIGKILL"}, p.SignalRules[0].Signals)
	assert.Equal(t, "external", p.SignalRules[0].Target.Type)
	assert.Equal(t, "deny", p.SignalRules[0].Decision)
	assert.Equal(t, "audit", p.SignalRules[0].Fallback)
}
