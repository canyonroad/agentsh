package catalog

import (
	"context"
	"testing"
)

func TestLoadPostgresSnapshotLoadsRelationsColumnsAndFunctions(t *testing.T) {
	q := fakeQueryer{
		relations: [][]any{
			{uint32(10), "public", "orders", "r", "app"},
		},
		columns: [][]any{
			{uint32(10), "id", uint32(23), true, 1},
			{uint32(10), "note", uint32(25), false, 2},
		},
		functions: [][]any{
			{uint32(20), "public", "calculate_total", "integer", "s", true, uint32(23)},
		},
	}
	snap, err := LoadPostgresSnapshot(context.Background(), q)
	if err != nil {
		t.Fatalf("LoadPostgresSnapshot: %v", err)
	}
	rel, ok := snap.RelationByName(Name{Schema: "public", Name: "orders"})
	if !ok || rel.OID != 10 || rel.Kind != RelationTable {
		t.Fatalf("loaded relation = %+v, %v", rel, ok)
	}
	if len(rel.Columns) != 2 || rel.Columns[0].Name != "id" || rel.Columns[1].TypeOID != 25 {
		t.Fatalf("loaded columns = %+v", rel.Columns)
	}
	fn, ok := snap.FunctionByOID(20)
	if !ok || fn.Volatility != VolatilityStable || !fn.Strict {
		t.Fatalf("loaded function = %+v, %v", fn, ok)
	}
}
