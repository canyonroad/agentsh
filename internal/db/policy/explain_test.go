package policy

import (
	"testing"

	"github.com/agentsh/agentsh/internal/db/effects"
)

func TestExplainStatement_ReturnsCoverageAndDecision(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: canonical-read, db_service: appdb, operations: [READ], relations: ["public.users"], match_object_resolution: catalog_resolved, decision: allow}
`)
	stmt := effects.ClassifiedStatement{RawVerb: "SELECT", Effects: []effects.Effect{{
		Group:      effects.GroupRead,
		Resolution: effects.ResolutionCatalogResolved,
		Objects:    []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "users"}},
		ResolvedObjects: []effects.ResolvedObjectRef{{
			Source: effects.ResolvedObjectSourceCatalog,
			Kind:   effects.ResolvedObjectRelation,
			Schema: "public",
			Name:   "users",
		}},
	}}}

	ex := ExplainStatement(stmt, rs, "appdb")
	if ex.Decision.Verb != VerbAllow || ex.Decision.RuleName != "canonical-read" {
		t.Fatalf("decision = %+v", ex.Decision)
	}
	if len(ex.Effects) != 1 || len(ex.Effects[0].Coverage) != 1 {
		t.Fatalf("coverage = %+v", ex.Effects)
	}
	cov := ex.Effects[0].Coverage[0]
	if !cov.Covered {
		t.Fatalf("coverage = %+v, want covered", cov)
	}
	if len(cov.CoveringRules) != 1 || cov.CoveringRules[0].RuleName != "canonical-read" {
		t.Fatalf("covering rules = %+v", cov.CoveringRules)
	}
	if cov.CoveringRules[0].Selector != "relations" {
		t.Fatalf("selector = %q, want relations", cov.CoveringRules[0].Selector)
	}
}

func TestExplainStatement_ReportsUncoveredObject(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: read-users, db_service: appdb, operations: [READ], objects: ["users"], decision: allow}
`)
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{{
		Group:      effects.GroupRead,
		Resolution: effects.ResolutionQualified,
		Objects:    []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "payments"}},
	}}}

	ex := ExplainStatement(stmt, rs, "appdb")
	if ex.Decision.Verb != VerbDeny || ex.Decision.RuleName != "" {
		t.Fatalf("decision = %+v, want implicit deny", ex.Decision)
	}
	if len(ex.Effects) != 1 || len(ex.Effects[0].Coverage) != 1 {
		t.Fatalf("coverage = %+v", ex.Effects)
	}
	cov := ex.Effects[0].Coverage[0]
	if cov.Covered || cov.UncoveredReason == "" {
		t.Fatalf("coverage = %+v, want uncovered reason", cov)
	}
}

func TestExplainStatement_ResolvedOnlyFunctionReportsFunctionCoverage(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: safe-fn, db_service: appdb, operations: [procedural], functions: ["public.safe_fn(integer)"], match_object_resolution: catalog_resolved, decision: allow}
`)
	oid := int32(2200)
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{{
		Group:       effects.GroupProcedural,
		Resolution:  effects.ResolutionCatalogResolved,
		FunctionOID: &oid,
		ResolvedObjects: []effects.ResolvedObjectRef{{
			Source:               effects.ResolvedObjectSourceCatalog,
			Kind:                 effects.ResolvedObjectFunction,
			OID:                  2200,
			Schema:               "public",
			Name:                 "safe_fn",
			FunctionIdentityArgs: "integer",
		}},
	}}}

	ex := ExplainStatement(stmt, rs, "appdb")
	if ex.Decision.Verb != VerbAllow || ex.Decision.RuleName != "safe-fn" {
		t.Fatalf("decision = %+v, want allow by safe-fn", ex.Decision)
	}
	if len(ex.Effects) != 1 || len(ex.Effects[0].CoveringRules) != 1 {
		t.Fatalf("effect explanation = %+v, want one covering rule", ex.Effects)
	}
	match := ex.Effects[0].CoveringRules[0]
	if match.RuleName != "safe-fn" || match.Selector != "functions" {
		t.Fatalf("covering rule = %+v, want safe-fn functions", match)
	}
	if len(ex.Effects[0].Coverage) != 0 {
		t.Fatalf("coverage = %+v, want no object coverage", ex.Effects[0].Coverage)
	}
}

func TestExplainStatement_ResolvedOnlyFunctionReportsBroadDeny(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: deny-procedural, db_service: appdb, operations: [procedural], decision: deny}
  - {name: safe-fn, db_service: appdb, operations: [procedural], functions: ["public.safe_fn(integer)"], match_object_resolution: catalog_resolved, decision: allow}
`)
	oid := int32(2200)
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{{
		Group:       effects.GroupProcedural,
		Resolution:  effects.ResolutionCatalogResolved,
		FunctionOID: &oid,
		ResolvedObjects: []effects.ResolvedObjectRef{{
			Source:               effects.ResolvedObjectSourceCatalog,
			Kind:                 effects.ResolvedObjectFunction,
			OID:                  2200,
			Schema:               "public",
			Name:                 "safe_fn",
			FunctionIdentityArgs: "integer",
		}},
	}}}

	ex := ExplainStatement(stmt, rs, "appdb")
	if ex.Decision.Verb != VerbDeny || ex.Decision.RuleName != "deny-procedural" {
		t.Fatalf("decision = %+v, want deny by deny-procedural", ex.Decision)
	}
	if len(ex.Effects) != 1 || len(ex.Effects[0].DenyRules) != 1 {
		t.Fatalf("effect explanation = %+v, want one deny rule", ex.Effects)
	}
	match := ex.Effects[0].DenyRules[0]
	if match.RuleName != "deny-procedural" || match.Selector != "all" {
		t.Fatalf("deny rule = %+v, want deny-procedural all", match)
	}
}

func TestExplainStatement_ObjectlessEffectReportsBroadCoverage(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: tx-allow, db_service: appdb, operations: [transaction], decision: allow}
`)
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{{
		Group: effects.GroupTransaction,
	}}}

	ex := ExplainStatement(stmt, rs, "appdb")
	if ex.Decision.Verb != VerbAllow || ex.Decision.RuleName != "tx-allow" {
		t.Fatalf("decision = %+v, want allow by tx-allow", ex.Decision)
	}
	if len(ex.Effects) != 1 || len(ex.Effects[0].CoveringRules) != 1 {
		t.Fatalf("effect explanation = %+v, want one covering rule", ex.Effects)
	}
	match := ex.Effects[0].CoveringRules[0]
	if match.RuleName != "tx-allow" || match.Selector != "all" {
		t.Fatalf("covering rule = %+v, want tx-allow all", match)
	}
	if len(ex.Effects[0].Coverage) != 0 {
		t.Fatalf("coverage = %+v, want no object coverage", ex.Effects[0].Coverage)
	}
}

func TestExplainStatement_DeDuplicatesDenyRules(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: deny-read, db_service: appdb, operations: [READ], decision: deny}
`)
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{{
		Group:      effects.GroupRead,
		Resolution: effects.ResolutionQualified,
		Objects: []effects.ObjectRef{
			{Kind: effects.ObjectTable, Name: "users"},
			{Kind: effects.ObjectTable, Name: "payments"},
		},
	}}}

	ex := ExplainStatement(stmt, rs, "appdb")
	if ex.Decision.Verb != VerbDeny || ex.Decision.RuleName != "deny-read" {
		t.Fatalf("decision = %+v, want deny by deny-read", ex.Decision)
	}
	if len(ex.Effects) != 1 || len(ex.Effects[0].DenyRules) != 1 {
		t.Fatalf("deny rules = %+v, want one de-duplicated deny rule", ex.Effects)
	}
	match := ex.Effects[0].DenyRules[0]
	if match.RuleName != "deny-read" || match.Selector != "all" {
		t.Fatalf("deny rule = %+v, want deny-read all", match)
	}
}
