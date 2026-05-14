package catalog

import "testing"

func TestResolveQualifiedRelation(t *testing.T) {
	snap := NewSnapshot([]Relation{{OID: 10, Name: Name{Schema: "public", Name: "orders"}, Kind: RelationTable}}, nil)
	got := ResolveRelation(snap, Name{Schema: "public", Name: "orders"}, nil)
	if !got.OK() || got.Relation.OID != 10 {
		t.Fatalf("ResolveRelation qualified = %+v", got)
	}
}

func TestResolveUnqualifiedRelationUsesSearchPath(t *testing.T) {
	snap := NewSnapshot([]Relation{
		{OID: 10, Name: Name{Schema: "public", Name: "orders"}, Kind: RelationTable},
		{OID: 11, Name: Name{Schema: "tenant", Name: "orders"}, Kind: RelationTable},
	}, nil)
	got := ResolveRelation(snap, Name{Name: "orders"}, []string{"tenant", "public"})
	if !got.OK() || got.Relation.OID != 11 {
		t.Fatalf("ResolveRelation search path = %+v", got)
	}
}

func TestResolveUnqualifiedRelationReportsAmbiguousWithoutSearchPathMatch(t *testing.T) {
	snap := NewSnapshot([]Relation{
		{OID: 10, Name: Name{Schema: "public", Name: "orders"}, Kind: RelationTable},
		{OID: 11, Name: Name{Schema: "tenant", Name: "orders"}, Kind: RelationTable},
	}, nil)
	got := ResolveRelation(snap, Name{Name: "orders"}, []string{"missing"})
	if got.Reason != UnresolvedAmbiguous {
		t.Fatalf("ambiguous reason = %s", got.Reason.String())
	}
}

func TestResolveUnqualifiedRelationReportsMissingWhenOnlyCandidateOutsideSearchPath(t *testing.T) {
	snap := NewSnapshot([]Relation{
		{OID: 10, Name: Name{Schema: "private", Name: "orders"}, Kind: RelationTable},
	}, nil)
	got := ResolveRelation(snap, Name{Name: "orders"}, []string{"public"})
	if got.Reason != UnresolvedMissing {
		t.Fatalf("reason = %s, want missing", got.Reason.String())
	}
}

func TestResolveUnqualifiedRelationReportsMissing(t *testing.T) {
	snap := NewSnapshot(nil, nil)
	got := ResolveRelation(snap, Name{Name: "orders"}, []string{"public"})
	if got.Reason != UnresolvedMissing {
		t.Fatalf("missing reason = %s", got.Reason.String())
	}
}

func TestResolveFunctionByOID(t *testing.T) {
	snap := NewSnapshot(nil, []Function{
		{OID: 20, Name: Name{Schema: "public", Name: "calculate_total"}, IdentityArgs: "integer"},
	})
	got := ResolveFunctionByOID(snap, 20)
	if !got.OK() || got.Function.Name.String() != "public.calculate_total" {
		t.Fatalf("ResolveFunctionByOID = %+v", got)
	}
}
