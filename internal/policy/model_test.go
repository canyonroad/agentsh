package policy

import (
	"testing"

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
