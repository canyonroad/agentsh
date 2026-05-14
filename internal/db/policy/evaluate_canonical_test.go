package policy

import (
	"testing"

	"github.com/agentsh/agentsh/internal/db/effects"
)

func TestEvaluate_RelationSelectorCoversResolvedRelation(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: canonical-read, db_service: appdb, operations: [READ], relations: ["public.users"], match_object_resolution: catalog_resolved, decision: allow}
`)
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{{
		Group:      effects.GroupRead,
		Resolution: effects.ResolutionCatalogResolved,
		Objects:    []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "users"}},
		ResolvedObjects: []effects.ResolvedObjectRef{{
			Source: effects.ResolvedObjectSourceCatalog,
			Kind:   effects.ResolvedObjectRelation,
			OID:    16384,
			Schema: "public",
			Name:   "users",
		}},
	}}}

	d := Evaluate(stmt, rs, "appdb")
	if d.Verb != VerbAllow || d.RuleName != "canonical-read" {
		t.Fatalf("decision = %+v, want allow by canonical-read", d)
	}
}

func TestEvaluate_RelationSelectorDoesNotCoverUnresolvedRelation(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: canonical-read, db_service: appdb, operations: [READ], relations: ["public.users"], match_object_resolution: catalog_unresolved, decision: allow}
`)
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{{
		Group:      effects.GroupRead,
		Resolution: effects.ResolutionCatalogUnresolved,
		Objects:    []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "users"}},
		ResolvedObjects: []effects.ResolvedObjectRef{{
			Source:           effects.ResolvedObjectSourceCatalog,
			Kind:             effects.ResolvedObjectRelation,
			Schema:           "public",
			Name:             "users",
			UnresolvedReason: "missing",
		}},
	}}}

	d := Evaluate(stmt, rs, "appdb")
	if d.Verb != VerbDeny || d.RuleName != "" {
		t.Fatalf("decision = %+v, want implicit deny", d)
	}
}

func TestEvaluate_RelationSelectorDoesNotCoverCompressedNonRelationSlot(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: trigger-create, db_service: appdb, operations: [CREATE], objects: ["users"], relations: ["public.users"], decision: allow}
`)
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{{
		Group:      effects.GroupSchemaCreate,
		Resolution: effects.ResolutionCatalogResolved,
		Objects: []effects.ObjectRef{
			{Kind: effects.ObjectFunction, Name: "trg"},
			{Kind: effects.ObjectTable, Name: "users"},
		},
		ResolvedObjects: []effects.ResolvedObjectRef{{
			Source: effects.ResolvedObjectSourceCatalog,
			Kind:   effects.ResolvedObjectRelation,
			OID:    16384,
			Schema: "public",
			Name:   "users",
		}},
	}}}

	d := Evaluate(stmt, rs, "appdb")
	if d.Verb != VerbDeny || d.RuleName != "" {
		t.Fatalf("decision = %+v, want implicit deny", d)
	}
}

func TestEvaluate_FunctionSelectorCoversResolvedFunction(t *testing.T) {
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

	d := Evaluate(stmt, rs, "appdb")
	if d.Verb != VerbAllow || d.RuleName != "safe-fn" {
		t.Fatalf("decision = %+v, want allow by safe-fn", d)
	}
}

func TestEvaluate_ResolvedOnlyBroadDenyPrecedesFunctionAllow(t *testing.T) {
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

	d := Evaluate(stmt, rs, "appdb")
	if d.Verb != VerbDeny || d.RuleName != "deny-procedural" {
		t.Fatalf("decision = %+v, want deny by deny-procedural", d)
	}
}

func TestEvaluate_ResolvedOnlyRelationDoesNotUseFunctionPath(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: read-all, db_service: appdb, operations: [READ], decision: allow}
`)
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{{
		Group:      effects.GroupRead,
		Resolution: effects.ResolutionCatalogResolved,
		ResolvedObjects: []effects.ResolvedObjectRef{{
			Source: effects.ResolvedObjectSourceCatalog,
			Kind:   effects.ResolvedObjectRelation,
			OID:    16384,
			Schema: "public",
			Name:   "users",
		}},
	}}}

	d := Evaluate(stmt, rs, "appdb")
	if d.Verb != VerbDeny || d.RuleName != "" {
		t.Fatalf("decision = %+v, want implicit deny", d)
	}
}

func TestEvaluate_FunctionSelectorRequiresResolvedSchemaMatch(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: sales-fn, db_service: appdb, operations: [procedural], schemas: ["sales"], functions: ["*"], match_object_resolution: catalog_resolved, decision: allow}
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

	d := Evaluate(stmt, rs, "appdb")
	if d.Verb != VerbDeny || d.RuleName != "" {
		t.Fatalf("decision = %+v, want implicit deny", d)
	}
}

func TestEvaluate_AuditTiePrimaryUsesPolicyOrderAcrossObjects(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: audit-orders, db_service: appdb, operations: [READ], objects: ["orders"], decision: audit}
  - {name: audit-users, db_service: appdb, operations: [READ], objects: ["users"], decision: audit}
`)
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{{
		Group: effects.GroupRead,
		Objects: []effects.ObjectRef{
			{Kind: effects.ObjectTable, Name: "users"},
			{Kind: effects.ObjectTable, Name: "orders"},
		},
	}}}

	d := Evaluate(stmt, rs, "appdb")
	if d.Verb != VerbAudit || d.RuleName != "audit-orders" {
		t.Fatalf("decision = %+v, want audit by audit-orders", d)
	}
}

func TestEvaluate_SchemasMatchesResolvedSchema(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: sales-read, db_service: appdb, operations: [READ], schemas: ["sales"], relations: ["sales.orders"], match_object_resolution: catalog_resolved, decision: allow}
`)
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{{
		Group:      effects.GroupRead,
		Resolution: effects.ResolutionCatalogResolved,
		Objects:    []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "orders"}},
		ResolvedObjects: []effects.ResolvedObjectRef{{
			Source: effects.ResolvedObjectSourceCatalog,
			Kind:   effects.ResolvedObjectRelation,
			Schema: "sales",
			Name:   "orders",
		}},
	}}}

	d := Evaluate(stmt, rs, "appdb")
	if d.Verb != VerbAllow || d.RuleName != "sales-read" {
		t.Fatalf("decision = %+v, want allow by sales-read", d)
	}
}

func TestEvaluate_MixedSelectorsCoverByEitherFamily(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: migration-read, db_service: appdb, operations: [READ], objects: ["legacy_users"], relations: ["public.users"], decision: allow}
`)
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{{
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

	d := Evaluate(stmt, rs, "appdb")
	if d.Verb != VerbAllow || d.RuleName != "migration-read" {
		t.Fatalf("decision = %+v, want allow by migration-read", d)
	}
}
