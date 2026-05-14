package policyexplain

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/agentsh/agentsh/internal/db/catalog"
	"github.com/agentsh/agentsh/internal/db/effects"
	dbpolicy "github.com/agentsh/agentsh/internal/db/policy"
	rootpolicy "github.com/agentsh/agentsh/internal/policy"
)

func TestRun_WithCatalogFixtureAllowsCanonicalRelation(t *testing.T) {
	rs := loadRuleSetForExplain(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: canonical-read, db_service: appdb, operations: [READ], relations: ["public.users"], match_object_resolution: catalog_resolved, decision: allow}
`)
	dir := t.TempDir()
	fixture := filepath.Join(dir, "catalog.yaml")
	if err := os.WriteFile(fixture, []byte(`search_path: [public]
relations:
  - oid: 16384
    schema: public
    name: users
    kind: table
`), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	report, err := Run(rs, []dbpolicy.Warning(nil), Options{
		SQL:            "SELECT * FROM users",
		Service:        "appdb",
		Dialect:        "postgres",
		CatalogFixture: fixture,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.CatalogSource != "fixture" {
		t.Fatalf("CatalogSource = %q", report.CatalogSource)
	}
	if len(report.Statements) != 1 {
		t.Fatalf("statements = %d", len(report.Statements))
	}
	dec := report.Statements[0].Decision
	if dec.Verb != "allow" || dec.RuleName != "canonical-read" {
		t.Fatalf("decision = %+v", dec)
	}
}

func TestRun_WithSearchPathAndCatalogFixtureAllowsCanonicalRelation(t *testing.T) {
	rs := loadRuleSetForExplain(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: canonical-read, db_service: appdb, operations: [READ], relations: ["public.users"], match_object_resolution: catalog_resolved, decision: allow}
`)
	fixture := writeUsersFixture(t)
	report, err := Run(rs, nil, Options{
		SQL:            "SELECT * FROM users",
		Service:        "appdb",
		Dialect:        "postgres",
		SearchPath:     []string{"public"},
		CatalogFixture: fixture,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(report.Statements) != 1 || len(report.Statements[0].Effects) != 1 {
		t.Fatalf("report statements = %+v", report.Statements)
	}
	eff := report.Statements[0].Effects[0]
	if eff.Resolution == effects.ResolutionAmbiguousAfterSearchPath.String() {
		t.Fatalf("resolution = %q, want non-stale search path", eff.Resolution)
	}
	dec := report.Statements[0].Decision
	if dec.Verb != "allow" || dec.RuleName != "canonical-read" {
		t.Fatalf("decision = %+v", dec)
	}
}

func TestRun_SearchPathInitializesDefaultSearchPath(t *testing.T) {
	rs := loadRuleSetForExplain(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: unqualified-read, db_service: appdb, operations: [READ], objects: ["users"], match_object_resolution: unqualified_syntactic, decision: allow}
`)
	report, err := Run(rs, nil, Options{
		SQL:        "SELECT * FROM users",
		Service:    "appdb",
		Dialect:    "postgres",
		SearchPath: []string{"public"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(report.Statements) != 1 || len(report.Statements[0].Effects) != 1 {
		t.Fatalf("report statements = %+v", report.Statements)
	}
	if got := report.Statements[0].Effects[0].Resolution; got != effects.ResolutionUnqualified.String() {
		t.Fatalf("resolution = %q, want %q", got, effects.ResolutionUnqualified)
	}
	dec := report.Statements[0].Decision
	if dec.Verb != "allow" || dec.RuleName != "unqualified-read" {
		t.Fatalf("decision = %+v", dec)
	}
}

func TestRun_WithoutCatalogFixtureWarnsForCanonicalSelectors(t *testing.T) {
	rs := loadRuleSetForExplain(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: canonical-read, db_service: appdb, operations: [READ], relations: ["public.users"], match_object_resolution: catalog_resolved, decision: allow}
`)
	report, err := Run(rs, nil, Options{
		SQL:        "SELECT * FROM users",
		Service:    "appdb",
		Dialect:    "postgres",
		SearchPath: []string{"public"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.CatalogSource != "none" {
		t.Fatalf("CatalogSource = %q, want none", report.CatalogSource)
	}
	dec := report.Statements[0].Decision
	if dec.Verb != "deny" || dec.RuleName != "" {
		t.Fatalf("decision = %+v, want implicit deny without fixture resolution", dec)
	}
	assertExplainWarning(t, report.Warnings, "catalog_fixture_missing_for_canonical_selector")
}

func TestResolveEffect_MixedRelationSkipsUnsupportedSlotsAndPolicyStillDenies(t *testing.T) {
	fixture := catalogFixtureForUsers()
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{{
		Group:      effects.GroupSchemaCreate,
		Resolution: effects.ResolutionUnqualified,
		Objects: []effects.ObjectRef{
			{Kind: effects.ObjectFunction, Name: "users_trigger"},
			{Kind: effects.ObjectTable, Name: "users"},
		},
	}}}

	got := resolveStatement(stmt, fixture)
	eff := got.Effects[0]
	if eff.Resolution != effects.ResolutionCatalogResolved {
		t.Fatalf("resolution = %v, want catalog_resolved", eff.Resolution)
	}
	if len(eff.ResolvedObjects) != 1 || eff.ResolvedObjects[0].CanonicalName() != "public.users" {
		t.Fatalf("resolved objects = %+v, want only public.users", eff.ResolvedObjects)
	}

	rs := loadRuleSetForExplain(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: create-users, db_service: appdb, operations: [CREATE], objects: ["users"], relations: ["public.users"], decision: allow}
`)
	ex := dbpolicy.ExplainStatement(got, rs, "appdb")
	if ex.Decision.Verb != dbpolicy.VerbDeny || ex.Decision.RuleName != "" {
		t.Fatalf("decision = %+v, want implicit deny for trigger object", ex.Decision)
	}
}

func TestResolveEffect_DuplicateRelationNamesPreserveSlotOrder(t *testing.T) {
	fixture := catalogFixtureForDuplicateUsers()
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{{
		Group:      effects.GroupRead,
		Resolution: effects.ResolutionUnqualified,
		Objects: []effects.ObjectRef{
			{Kind: effects.ObjectTable, Schema: "public", Name: "users"},
			{Kind: effects.ObjectTable, Name: "users"},
		},
	}}}

	got := resolveStatement(stmt, fixture)
	eff := got.Effects[0]
	if eff.Resolution != effects.ResolutionCatalogResolved {
		t.Fatalf("resolution = %v, want catalog_resolved", eff.Resolution)
	}
	if len(eff.ResolvedObjects) != 2 {
		t.Fatalf("resolved objects = %+v, want two resolved relations", eff.ResolvedObjects)
	}
	if eff.ResolvedObjects[0].CanonicalName() != "public.users" || eff.ResolvedObjects[1].CanonicalName() != "audit.users" {
		t.Fatalf("resolved objects = %+v, want public.users then audit.users", eff.ResolvedObjects)
	}

	rs := loadRuleSetForExplain(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: public-users, db_service: appdb, operations: [READ], relations: ["public.users"], match_object_resolution: catalog_resolved, decision: allow}
`)
	ex := dbpolicy.ExplainStatement(got, rs, "appdb")
	if ex.Decision.Verb != dbpolicy.VerbDeny || ex.Decision.RuleName != "" {
		t.Fatalf("decision = %+v, want implicit deny because second users slot resolved to audit.users", ex.Decision)
	}
}

func TestResolveStatements_InvalidatesFixtureAfterRoleChange(t *testing.T) {
	stmts := []effects.ClassifiedStatement{{
		RawVerb: "SET_ROLE=app",
		Effects: []effects.Effect{{
			Group:   effects.GroupSession,
			Subtype: effects.SubtypeSetRole,
			Objects: []effects.ObjectRef{{Kind: effects.ObjectRole, Name: "app"}},
		}},
	}, {
		RawVerb: "SELECT",
		Effects: []effects.Effect{{
			Group:      effects.GroupRead,
			Resolution: effects.ResolutionUnqualified,
			Objects:    []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "users"}},
		}},
	}}

	got := resolveStatements(stmts, catalogFixtureForUsers())
	eff := got[1].Effects[0]
	if eff.Resolution != effects.ResolutionCatalogUnavailable {
		t.Fatalf("second statement resolution = %v, want catalog_unavailable", eff.Resolution)
	}
	if len(eff.ResolvedObjects) != 1 || eff.ResolvedObjects[0].UnresolvedReason != "session_state_changed" {
		t.Fatalf("second statement resolved objects = %+v", eff.ResolvedObjects)
	}

	rs := loadRuleSetForExplain(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: canonical-read, db_service: appdb, operations: [READ], relations: ["public.users"], match_object_resolution: catalog_resolved, decision: allow}
`)
	ex := dbpolicy.ExplainStatement(got[1], rs, "appdb")
	if ex.Decision.Verb != dbpolicy.VerbDeny || ex.Decision.RuleName != "" {
		t.Fatalf("decision = %+v, want canonical rule not to allow stale fixture resolution", ex.Decision)
	}
}

func TestResolveStatements_SetSearchPathUpdatesFixtureSearchPath(t *testing.T) {
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

	got := resolveStatements(stmts, catalogFixtureForDuplicateUsers())
	eff := got[1].Effects[0]
	if eff.Resolution != effects.ResolutionCatalogResolved {
		t.Fatalf("second statement resolution = %v, want catalog_resolved", eff.Resolution)
	}
	if len(eff.ResolvedObjects) != 1 || eff.ResolvedObjects[0].CanonicalName() != "audit.users" {
		t.Fatalf("second statement resolved objects = %+v, want audit.users", eff.ResolvedObjects)
	}
}

func TestResolveStatements_TransactionBoundaryWithoutLocalSearchPathKeepsFixture(t *testing.T) {
	stmts := []effects.ClassifiedStatement{{
		RawVerb: "COMMIT",
		Effects: []effects.Effect{{
			Group: effects.GroupTransaction,
		}},
	}, {
		RawVerb: "SELECT",
		Effects: []effects.Effect{{
			Group:      effects.GroupRead,
			Resolution: effects.ResolutionUnqualified,
			Objects:    []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "users"}},
		}},
	}}

	got := resolveStatements(stmts, catalogFixtureForUsers())
	eff := got[1].Effects[0]
	if eff.Resolution != effects.ResolutionCatalogResolved {
		t.Fatalf("second statement resolution = %v, want catalog_resolved", eff.Resolution)
	}
	if len(eff.ResolvedObjects) != 1 || eff.ResolvedObjects[0].CanonicalName() != "public.users" {
		t.Fatalf("second statement resolved objects = %+v, want public.users", eff.ResolvedObjects)
	}
}

func TestResolveStatements_InvalidatesFixtureAfterSchemaAlterWithoutSubtype(t *testing.T) {
	stmts := []effects.ClassifiedStatement{{
		RawVerb: "ALTER_TABLE",
		Effects: []effects.Effect{{
			Group:      effects.GroupSchemaAlter,
			Resolution: effects.ResolutionUnqualified,
			Objects:    []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "users"}},
		}},
	}, {
		RawVerb: "SELECT",
		Effects: []effects.Effect{{
			Group:      effects.GroupRead,
			Resolution: effects.ResolutionUnqualified,
			Objects:    []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "users"}},
		}},
	}}

	got := resolveStatements(stmts, catalogFixtureForUsers())
	eff := got[1].Effects[0]
	if eff.Resolution != effects.ResolutionCatalogUnavailable {
		t.Fatalf("second statement resolution = %v, want catalog_unavailable", eff.Resolution)
	}
	if len(eff.ResolvedObjects) != 1 || eff.ResolvedObjects[0].UnresolvedReason != "session_state_changed" {
		t.Fatalf("second statement resolved objects = %+v", eff.ResolvedObjects)
	}
}

func loadRuleSetForExplain(t *testing.T, src string) *dbpolicy.RuleSet {
	t.Helper()
	p, err := rootpolicy.LoadFromBytes([]byte(src))
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	rs, _, err := dbpolicy.Decode(p)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	return rs
}

func assertExplainWarning(t *testing.T, warns []WarningReport, code string) {
	t.Helper()
	for _, w := range warns {
		if w.Code == code {
			return
		}
	}
	t.Fatalf("warnings = %+v, want code %q", warns, code)
}

func writeUsersFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	fixture := filepath.Join(dir, "catalog.yaml")
	if err := os.WriteFile(fixture, []byte(`search_path: [public]
relations:
  - oid: 16384
    schema: public
    name: users
    kind: table
`), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return fixture
}

func catalogFixtureForUsers() CatalogFixture {
	return CatalogFixture{
		SearchPath: []string{"public"},
		Snapshot: catalog.NewSnapshot([]catalog.Relation{{
			OID:  catalog.OID(16384),
			Name: catalog.Name{Schema: "public", Name: "users"},
			Kind: catalog.RelationTable,
		}}, nil),
	}
}

func catalogFixtureForDuplicateUsers() CatalogFixture {
	return CatalogFixture{
		SearchPath: []string{"audit", "public"},
		Snapshot: catalog.NewSnapshot([]catalog.Relation{{
			OID:  catalog.OID(16384),
			Name: catalog.Name{Schema: "public", Name: "users"},
			Kind: catalog.RelationTable,
		}, {
			OID:  catalog.OID(16385),
			Name: catalog.Name{Schema: "audit", Name: "users"},
			Kind: catalog.RelationTable,
		}}, nil),
	}
}
