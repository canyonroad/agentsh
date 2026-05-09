package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolvePolicyPathFindsVariants(t *testing.T) {
	dir := t.TempDir()
	paths := []string{
		filepath.Join(dir, "name.yaml"),
		filepath.Join(dir, "name.yml"),
		filepath.Join(dir, "name"),
	}
	// create only .yml and bare name; should pick first existing in order.
	if err := os.WriteFile(paths[1], []byte("version: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := ResolvePolicyPath(dir, "name")
	if err != nil {
		t.Fatalf("ResolvePolicyPath error: %v", err)
	}
	if p != paths[1] {
		t.Fatalf("expected %s, got %s", paths[1], p)
	}
}

func TestResolvePolicyPathNotFound(t *testing.T) {
	if _, err := ResolvePolicyPath(t.TempDir(), "missing"); err == nil {
		t.Fatalf("expected not found error")
	}
}

func TestLoadAcceptsDBRuleFamilies(t *testing.T) {
	yaml := []byte(`
version: 1
name: db-test
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: db.internal:5432
    tls_mode: terminate_reissue
database_rules:
  - name: r1
    db_service: appdb
    operations: [READ]
    decision: allow
database_connection_rules:
  - name: c1
    db_service: appdb
    decision: allow
`)
	if _, err := LoadFromBytes(yaml); err != nil {
		t.Fatalf("LoadFromBytes rejected DB rule families: %v", err)
	}
}
