package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestRoot_WiresPolicyAndConfig(t *testing.T) {
	root := NewRoot("test")
	foundPolicy := false
	foundConfig := false
	for _, c := range root.Commands() {
		if c.Name() == "policy" {
			foundPolicy = true
		}
		if c.Name() == "config" {
			foundConfig = true
		}
	}
	if !foundPolicy {
		t.Fatalf("expected policy command to be registered")
	}
	if !foundConfig {
		t.Fatalf("expected config command to be registered")
	}
}

func TestPolicyValidate_PrintsDBWarnings(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	writeFile(t, policyPath, `version: 1
name: t
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: x:1
    tls_mode: terminate_reissue
database_rules:
  - name: canonical-read
    db_service: appdb
    operations: [READ]
    relations: ["public.users"]
    decision: allow
`)

	root := NewRoot("test")
	var out bytes.Buffer
	var errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs([]string{"policy", "validate", policyPath})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v\nstdout:\n%s\nstderr:\n%s", err, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "ok") {
		t.Fatalf("stdout = %q, want ok", out.String())
	}
	if !strings.Contains(errOut.String(), "warning[canonical_selector_without_resolution_guard]") {
		t.Fatalf("stderr = %q, want canonical selector warning", errOut.String())
	}
}
