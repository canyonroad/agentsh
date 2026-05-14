package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyDBExplainJSONWithSQLFlag(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	fixturePath := filepath.Join(dir, "catalog.yaml")
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
    match_object_resolution: catalog_resolved
    decision: allow
`)
	writeFile(t, fixturePath, `search_path: [public]
relations:
  - oid: 16384
    schema: public
    name: users
    kind: table
`)

	root := NewRoot("test")
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"policy", "db", "explain", policyPath, "--service", "appdb", "--catalog-fixture", fixturePath, "--sql", "SELECT * FROM users"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v\n%s", err, out.String())
	}
	body := out.String()
	if !strings.Contains(body, `"verb": "allow"`) {
		t.Fatalf("missing allow decision:\n%s", body)
	}
	if !strings.Contains(body, `"rule_name": "canonical-read"`) {
		t.Fatalf("missing rule name:\n%s", body)
	}
	if !strings.Contains(body, `"resolved_object": "public.users"`) {
		t.Fatalf("missing resolved object:\n%s", body)
	}
}

func TestPolicyDBExplainTextFromStdin(t *testing.T) {
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
  - {name: read-all, db_service: appdb, operations: [READ], decision: allow}
`)
	root := NewRoot("test")
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetIn(strings.NewReader("SELECT * FROM users"))
	root.SetArgs([]string{"policy", "db", "explain", policyPath, "--service", "appdb", "--output", "text"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v\n%s", err, out.String())
	}
	body := out.String()
	if !strings.Contains(body, "decision: allow") || !strings.Contains(body, "rule: read-all") {
		t.Fatalf("unexpected text output:\n%s", body)
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
