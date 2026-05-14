package catalog

import "testing"

func TestRelationKindString(t *testing.T) {
	tests := map[RelationKind]string{
		RelationTable:            "table",
		RelationPartitionedTable: "partitioned_table",
		RelationView:             "view",
		RelationMaterializedView: "materialized_view",
		RelationForeignTable:     "foreign_table",
		RelationSequence:         "sequence",
	}
	for kind, want := range tests {
		if got := kind.String(); got != want {
			t.Fatalf("RelationKind(%d).String() = %q, want %q", kind, got, want)
		}
	}
}

func TestCanonicalNameString(t *testing.T) {
	name := Name{Schema: "public", Name: "orders"}
	if got := name.String(); got != "public.orders" {
		t.Fatalf("Name.String() = %q", got)
	}
}

func TestUnresolvedReasonString(t *testing.T) {
	if got := UnresolvedMissing.String(); got != "missing" {
		t.Fatalf("UnresolvedMissing.String() = %q", got)
	}
}
