//go:build linux

package postgres

import (
	"errors"
	"testing"

	"github.com/agentsh/agentsh/internal/db/catalog"
	classify_pg "github.com/agentsh/agentsh/internal/db/classify/postgres"
	"github.com/agentsh/agentsh/internal/db/effects"
)

func testCatalogContext() catalogRuntimeContext {
	return catalogRuntimeContext{
		Snapshot: catalog.NewSnapshot([]catalog.Relation{{
			OID:  10,
			Name: catalog.Name{Schema: "public", Name: "users"},
			Kind: catalog.RelationTable,
		}, {
			OID:  11,
			Name: catalog.Name{Schema: "audit", Name: "users"},
			Kind: catalog.RelationTable,
		}, {
			OID:  12,
			Name: catalog.Name{Schema: "public", Name: "active_users"},
			Kind: catalog.RelationView,
		}}, []catalog.Function{{
			OID:          99,
			Name:         catalog.Name{Schema: "public", Name: "normalize_email"},
			IdentityArgs: "text",
			Volatility:   catalog.VolatilityImmutable,
		}}),
		SearchPath: []string{"public"},
	}
}

func TestResolveStatementCatalog_QualifiedRelation(t *testing.T) {
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{{
		Group:      effects.GroupRead,
		Resolution: effects.ResolutionQualified,
		Objects:    []effects.ObjectRef{{Kind: effects.ObjectTable, Schema: "public", Name: "users"}},
	}}}
	got := resolveStatementCatalog(stmt, testCatalogContext())
	eff := got.Effects[0]
	if eff.Resolution != effects.ResolutionCatalogResolved {
		t.Fatalf("Resolution = %v", eff.Resolution)
	}
	if len(eff.ResolvedObjects) != 1 || eff.ResolvedObjects[0].OID != 10 {
		t.Fatalf("ResolvedObjects = %+v", eff.ResolvedObjects)
	}
}

func TestResolveStatementCatalog_UnqualifiedRelationUsesSearchPath(t *testing.T) {
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{{
		Group:      effects.GroupRead,
		Resolution: effects.ResolutionUnqualified,
		Objects:    []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "users"}},
	}}}
	got := resolveStatementCatalog(stmt, testCatalogContext())
	if got.Effects[0].ResolvedObjects[0].Schema != "public" {
		t.Fatalf("resolved schema = %+v", got.Effects[0].ResolvedObjects[0])
	}
}

func TestResolveStatementCatalog_MissingRelation(t *testing.T) {
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{{
		Group:      effects.GroupRead,
		Resolution: effects.ResolutionUnqualified,
		Objects:    []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "missing"}},
	}}}
	got := resolveStatementCatalog(stmt, testCatalogContext())
	eff := got.Effects[0]
	if eff.Resolution != effects.ResolutionCatalogUnresolved {
		t.Fatalf("Resolution = %v", eff.Resolution)
	}
	if eff.ResolvedObjects[0].UnresolvedReason != "missing" {
		t.Fatalf("reason = %+v", eff.ResolvedObjects[0])
	}
}

func TestResolveStatementCatalog_Unavailable(t *testing.T) {
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{{
		Group:      effects.GroupRead,
		Resolution: effects.ResolutionUnqualified,
		Objects:    []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "users"}},
	}}}
	got := resolveStatementCatalog(stmt, catalogRuntimeContext{UnavailableReason: "snapshot_load_failed"})
	if got.Effects[0].Resolution != effects.ResolutionCatalogUnavailable {
		t.Fatalf("Resolution = %v", got.Effects[0].Resolution)
	}
	if got.Effects[0].ResolvedObjects[0].UnresolvedReason != "snapshot_load_failed" {
		t.Fatalf("ResolvedObjects = %+v", got.Effects[0].ResolvedObjects)
	}
}

func TestResolveStatementCatalog_UnsupportedObjectKind(t *testing.T) {
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{{
		Group:      effects.GroupSession,
		Resolution: effects.ResolutionQualified,
		Objects:    []effects.ObjectRef{{Kind: effects.ObjectGUC, Name: "search_path"}},
	}}}
	got := resolveStatementCatalog(stmt, testCatalogContext())
	eff := got.Effects[0]
	if eff.Resolution != effects.ResolutionCatalogUnresolved {
		t.Fatalf("Resolution = %v", eff.Resolution)
	}
	if eff.ResolvedObjects[0].UnresolvedReason != "unsupported" {
		t.Fatalf("ResolvedObjects = %+v", eff.ResolvedObjects)
	}
}

func TestResolveStatementCatalog_MixedEffectSkipsNonCatalogObject(t *testing.T) {
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{{
		Group:      effects.GroupBulkExport,
		Resolution: effects.ResolutionUnqualified,
		Objects: []effects.ObjectRef{
			{Kind: effects.ObjectTable, Name: "users"},
			{Kind: effects.ObjectProgram, Argv0: "psql"},
		},
	}}}
	got := resolveStatementCatalog(stmt, testCatalogContext())
	eff := got.Effects[0]
	if eff.Resolution != effects.ResolutionCatalogResolved {
		t.Fatalf("Resolution = %v", eff.Resolution)
	}
	if len(eff.ResolvedObjects) != 1 || eff.ResolvedObjects[0].OID != 10 {
		t.Fatalf("ResolvedObjects = %+v", eff.ResolvedObjects)
	}
}

func TestResolveStatementCatalog_FunctionOID(t *testing.T) {
	oid := int32(99)
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{{
		Group:       effects.GroupProcedural,
		Subtype:     effects.SubtypeFunctionCallProtocol,
		FunctionOID: &oid,
	}}}
	got := resolveStatementCatalog(stmt, testCatalogContext())
	eff := got.Effects[0]
	if eff.Resolution != effects.ResolutionCatalogResolved {
		t.Fatalf("Resolution = %v", eff.Resolution)
	}
	if len(eff.ResolvedObjects) != 1 || eff.ResolvedObjects[0].FunctionIdentityArgs != "text" {
		t.Fatalf("ResolvedObjects = %+v", eff.ResolvedObjects)
	}
}

func TestResolveStatementCatalog_FunctionOIDReplacesStaleResolvedObjects(t *testing.T) {
	oid := int32(99)
	stale := []effects.ResolvedObjectRef{{
		Source: effects.ResolvedObjectSourceCatalog,
		Kind:   effects.ResolvedObjectRelation,
		OID:    1234,
		Name:   "stale",
	}}
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{{
		Group:           effects.GroupProcedural,
		Subtype:         effects.SubtypeFunctionCallProtocol,
		FunctionOID:     &oid,
		ResolvedObjects: stale,
	}}}
	got := resolveStatementCatalog(stmt, testCatalogContext())
	eff := got.Effects[0]
	if len(eff.ResolvedObjects) != 1 || eff.ResolvedObjects[0].Kind != effects.ResolvedObjectFunction {
		t.Fatalf("ResolvedObjects = %+v", eff.ResolvedObjects)
	}
	if stmt.Effects[0].ResolvedObjects[0].Name != "stale" {
		t.Fatalf("input mutated = %+v", stmt.Effects[0].ResolvedObjects)
	}
}

func TestResolveStatementsCatalog_FailsClosedAfterSearchPathMutationInBatch(t *testing.T) {
	ctx := testCatalogContext()
	stmts := []effects.ClassifiedStatement{{
		RawVerb: "SET_SEARCH_PATH=audit,public",
		Effects: []effects.Effect{{
			Group:   effects.GroupSession,
			Subtype: effects.SubtypeSetSearchPath,
			Objects: []effects.ObjectRef{{Kind: effects.ObjectGUC, Name: "search_path"}},
		}},
	}, {
		RawVerb: "SELECT",
		Effects: []effects.Effect{{
			Group:      effects.GroupRead,
			Resolution: effects.ResolutionUnqualified,
			Objects:    []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "users"}},
		}},
	}}

	got := resolveStatementsCatalog(stmts, ctx)
	eff := got[1].Effects[0]
	if eff.Resolution != effects.ResolutionCatalogUnavailable {
		t.Fatalf("second statement resolution = %v, want catalog_unavailable", eff.Resolution)
	}
	if len(eff.ResolvedObjects) != 1 || eff.ResolvedObjects[0].UnresolvedReason != "session_state_changed" {
		t.Fatalf("second statement resolved objects = %+v", eff.ResolvedObjects)
	}
}

func TestResolveStatementsCatalog_FailsClosedAfterSetLocalSearchPathInBatch(t *testing.T) {
	ctx := testCatalogContext()
	stmts := []effects.ClassifiedStatement{{
		RawVerb: "SET_LOCAL=search_path:audit,public",
		Effects: []effects.Effect{{
			Group:   effects.GroupSession,
			Subtype: effects.SubtypeSetLocal,
			Objects: []effects.ObjectRef{{Kind: effects.ObjectGUC, Name: "search_path"}},
		}},
	}, {
		RawVerb: "SELECT",
		Effects: []effects.Effect{{
			Group:      effects.GroupRead,
			Resolution: effects.ResolutionUnqualified,
			Objects:    []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "users"}},
		}},
	}}

	got := resolveStatementsCatalog(stmts, ctx)
	eff := got[1].Effects[0]
	if eff.Resolution != effects.ResolutionCatalogUnavailable {
		t.Fatalf("second statement resolution = %v, want catalog_unavailable", eff.Resolution)
	}
	if len(eff.ResolvedObjects) != 1 || eff.ResolvedObjects[0].UnresolvedReason != "session_state_changed" {
		t.Fatalf("second statement resolved objects = %+v", eff.ResolvedObjects)
	}
}

func TestResolveStatementsCatalog_FailsClosedAfterResetSessionAuthorizationInBatch(t *testing.T) {
	ctx := testCatalogContext()
	stmts := []effects.ClassifiedStatement{{
		RawVerb: "RESET=session_authorization",
		Effects: []effects.Effect{{
			Group:   effects.GroupSession,
			Subtype: effects.SubtypeReset,
			Objects: []effects.ObjectRef{{Kind: effects.ObjectGUC, Name: "session_authorization"}},
		}},
	}, {
		RawVerb: "SELECT",
		Effects: []effects.Effect{{
			Group:      effects.GroupRead,
			Resolution: effects.ResolutionUnqualified,
			Objects:    []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "users"}},
		}},
	}}

	got := resolveStatementsCatalog(stmts, ctx)
	eff := got[1].Effects[0]
	if eff.Resolution != effects.ResolutionCatalogUnavailable {
		t.Fatalf("second statement resolution = %v, want catalog_unavailable", eff.Resolution)
	}
	if len(eff.ResolvedObjects) != 1 || eff.ResolvedObjects[0].UnresolvedReason != "session_state_changed" {
		t.Fatalf("second statement resolved objects = %+v", eff.ResolvedObjects)
	}
}

func TestResolvingParser_ClassifyErrorReturnsBaseStatementsUnresolved(t *testing.T) {
	classifyErr := errors.New("parse failed")
	oid := int32(99)
	baseStmts := []effects.ClassifiedStatement{{
		Effects: []effects.Effect{{
			Group:       effects.GroupProcedural,
			Subtype:     effects.SubtypeFunctionCallProtocol,
			FunctionOID: &oid,
		}},
	}}
	parser := resolvingParser{
		base: fakeRuntimeParser{stmts: baseStmts, err: classifyErr},
		ctx:  testCatalogContext(),
	}

	got, err := parser.Classify("select", classify_pg.SessionState{}, classify_pg.Options{})
	if !errors.Is(err, classifyErr) {
		t.Fatalf("err = %v", err)
	}
	if len(got) != 1 || len(got[0].Effects) != 1 {
		t.Fatalf("statements = %+v", got)
	}
	if got[0].Effects[0].Resolution == effects.ResolutionCatalogResolved || len(got[0].Effects[0].ResolvedObjects) != 0 {
		t.Fatalf("statements were resolved on error = %+v", got)
	}
}

type fakeRuntimeParser struct {
	stmts []effects.ClassifiedStatement
	err   error
}

func (p fakeRuntimeParser) Classify(string, classify_pg.SessionState, classify_pg.Options) ([]effects.ClassifiedStatement, error) {
	return p.stmts, p.err
}

func (p fakeRuntimeParser) Normalize(sql string) (string, error) {
	return sql, nil
}
