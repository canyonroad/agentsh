package catalog

import "testing"

func TestSnapshotRelationLookup(t *testing.T) {
	snap := NewSnapshot([]Relation{
		{OID: 10, Name: Name{Schema: "public", Name: "orders"}, Kind: RelationTable},
		{OID: 11, Name: Name{Schema: "audit", Name: "orders"}, Kind: RelationTable},
	}, nil)

	if rel, ok := snap.RelationByOID(10); !ok || rel.Name.String() != "public.orders" {
		t.Fatalf("RelationByOID(10) = %+v, %v", rel, ok)
	}
	if got := snap.RelationsByUnqualifiedName("orders"); len(got) != 2 {
		t.Fatalf("RelationsByUnqualifiedName returned %d candidates, want 2", len(got))
	}
	if rel, ok := snap.RelationByName(Name{Schema: "audit", Name: "orders"}); !ok || rel.OID != 11 {
		t.Fatalf("RelationByName(audit.orders) = %+v, %v", rel, ok)
	}
}

func TestSnapshotFunctionLookup(t *testing.T) {
	snap := NewSnapshot(nil, []Function{
		{OID: 20, Name: Name{Schema: "public", Name: "calculate_total"}, IdentityArgs: "integer"},
		{OID: 21, Name: Name{Schema: "public", Name: "calculate_total"}, IdentityArgs: "integer, integer"},
	})

	if fn, ok := snap.FunctionByOID(20); !ok || fn.IdentityArgs != "integer" {
		t.Fatalf("FunctionByOID(20) = %+v, %v", fn, ok)
	}
	if got := snap.FunctionsByName(Name{Schema: "public", Name: "calculate_total"}); len(got) != 2 {
		t.Fatalf("FunctionsByName returned %d candidates, want 2", len(got))
	}
}
