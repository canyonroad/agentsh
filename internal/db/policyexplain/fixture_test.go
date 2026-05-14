package policyexplain

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCatalogFixture(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.yaml")
	err := os.WriteFile(path, []byte(`search_path: [public, pg_catalog]
relations:
  - oid: 16384
    schema: public
    name: users
    kind: table
functions:
  - oid: 2200
    schema: public
    name: safe_fn
    identity_args: integer
    volatility: stable
    strict: true
    return_type_oid: 23
`), 0644)
	if err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	fixture, err := LoadCatalogFixture(path)
	if err != nil {
		t.Fatalf("LoadCatalogFixture: %v", err)
	}
	if got := fixture.SearchPath; len(got) != 2 || got[0] != "public" || got[1] != "pg_catalog" {
		t.Fatalf("SearchPath = %#v", got)
	}
	if rel, ok := fixture.Snapshot.RelationByOID(16384); !ok || rel.Name.String() != "public.users" {
		t.Fatalf("relation lookup = %+v, %v", rel, ok)
	}
	if fn, ok := fixture.Snapshot.FunctionByOID(2200); !ok || fn.IdentityArgs != "integer" {
		t.Fatalf("function lookup = %+v, %v", fn, ok)
	}
}
