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

func TestResolveStatements_InvalidatesFixtureAfterSessionStateChange(t *testing.T) {
	stmts := []effects.ClassifiedStatement{{
		RawVerb: "SET_SEARCH_PATH=app",
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
