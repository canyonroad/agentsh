package policy

import (
	"testing"

	"github.com/agentsh/agentsh/internal/db/effects"
)

func TestEvaluate_RedirectCoversResolvedRelation(t *testing.T) {
	rs := loadRules(t, redirectPolicy(`
  - name: redirect-users
    db_service: appdb
    operations: [READ]
    relations: ["public.users"]
    match_object_resolution: catalog_resolved
    decision: redirect
    redirect:
      relation: public.safe_users
`))

	d := Evaluate(catalogResolvedRead("public", "users"), rs, "appdb")
	if d.Verb != VerbRedirect {
		t.Fatalf("Verb = %v, want redirect; decision = %+v", d.Verb, d)
	}
	if d.RuleName != "redirect-users" {
		t.Errorf("RuleName = %q, want redirect-users", d.RuleName)
	}
	if d.Redirect == nil {
		t.Fatal("Redirect metadata nil")
	}
	if d.Redirect.SourceRelation != "public.users" {
		t.Errorf("SourceRelation = %q, want public.users", d.Redirect.SourceRelation)
	}
	if d.Redirect.TargetRelation != "public.safe_users" {
		t.Errorf("TargetRelation = %q, want public.safe_users", d.Redirect.TargetRelation)
	}

	d.Redirect.SourceRelation = "mutated.source"
	d.Redirect.TargetRelation = "mutated.target"
	d = Evaluate(catalogResolvedRead("public", "users"), rs, "appdb")
	if d.Redirect == nil || d.Redirect.SourceRelation != "public.users" || d.Redirect.TargetRelation != "public.safe_users" {
		t.Fatalf("Redirect after prior decision mutation = %+v, want fresh public.users -> public.safe_users", d.Redirect)
	}
}

func TestEvaluate_DenyBeatsRedirect(t *testing.T) {
	rs := loadRules(t, redirectPolicy(`
  - name: redirect-users
    db_service: appdb
    operations: [READ]
    relations: ["public.users"]
    match_object_resolution: catalog_resolved
    decision: redirect
    redirect:
      relation: public.safe_users
  - name: deny-users
    db_service: appdb
    operations: [READ]
    relations: ["public.users"]
    match_object_resolution: catalog_resolved
    decision: deny
`))

	d := Evaluate(catalogResolvedRead("public", "users"), rs, "appdb")
	if d.Verb != VerbDeny || d.RuleName != "deny-users" {
		t.Fatalf("decision = %+v, want deny by deny-users", d)
	}
	if d.Redirect != nil {
		t.Fatalf("Redirect = %+v, want nil", d.Redirect)
	}
}

func TestEvaluate_ApproveBeatsRedirect(t *testing.T) {
	rs := loadRules(t, redirectPolicy(`
  - name: redirect-users
    db_service: appdb
    operations: [READ]
    relations: ["public.users"]
    match_object_resolution: catalog_resolved
    decision: redirect
    redirect:
      relation: public.safe_users
  - name: approve-users
    db_service: appdb
    operations: [READ]
    relations: ["public.users"]
    match_object_resolution: catalog_resolved
    decision: approve
`))

	d := Evaluate(catalogResolvedRead("public", "users"), rs, "appdb")
	if d.Verb != VerbApprove || d.RuleName != "approve-users" {
		t.Fatalf("decision = %+v, want approve by approve-users", d)
	}
	if d.Redirect != nil {
		t.Fatalf("Redirect = %+v, want nil", d.Redirect)
	}
}

func TestEvaluate_RedirectBeatsAuditAndAllow(t *testing.T) {
	rs := loadRules(t, redirectPolicy(`
  - name: allow-users
    db_service: appdb
    operations: [READ]
    relations: ["public.users"]
    match_object_resolution: catalog_resolved
    decision: allow
  - name: audit-users
    db_service: appdb
    operations: [READ]
    relations: ["public.users"]
    match_object_resolution: catalog_resolved
    decision: audit
    acknowledge_audit_on_dangerous: true
  - name: redirect-users
    db_service: appdb
    operations: [READ]
    relations: ["public.users"]
    match_object_resolution: catalog_resolved
    decision: redirect
    redirect:
      relation: public.safe_users
`))

	d := Evaluate(catalogResolvedRead("public", "users"), rs, "appdb")
	if d.Verb != VerbRedirect || d.RuleName != "redirect-users" {
		t.Fatalf("decision = %+v, want redirect by redirect-users", d)
	}
}

func TestEvaluate_RedirectCoversOneRelationAndAllowCoversAnother(t *testing.T) {
	rs := loadRules(t, redirectPolicy(`
  - name: redirect-users
    db_service: appdb
    operations: [READ]
    relations: ["public.users"]
    match_object_resolution: catalog_resolved
    decision: redirect
    redirect:
      relation: public.safe_users
  - name: allow-orders
    db_service: appdb
    operations: [READ]
    relations: ["public.orders"]
    match_object_resolution: catalog_resolved
    decision: allow
`))

	stmt := catalogResolvedRead("public", "users")
	stmt.Effects[0].Objects = append(stmt.Effects[0].Objects, effects.ObjectRef{Kind: effects.ObjectTable, Name: "orders"})
	stmt.Effects[0].ResolvedObjects = append(stmt.Effects[0].ResolvedObjects, effects.ResolvedObjectRef{
		Source: effects.ResolvedObjectSourceCatalog,
		Kind:   effects.ResolvedObjectRelation,
		Schema: "public",
		Name:   "orders",
	})

	d := Evaluate(stmt, rs, "appdb")
	if d.Verb != VerbRedirect || d.RuleName != "redirect-users" {
		t.Fatalf("decision = %+v, want redirect by redirect-users", d)
	}
	if d.Redirect == nil {
		t.Fatal("Redirect metadata nil")
	}
	if d.Redirect.SourceRelation != "public.users" || d.Redirect.TargetRelation != "public.safe_users" {
		t.Fatalf("Redirect = %+v, want public.users -> public.safe_users", d.Redirect)
	}
}

func TestEvaluate_TwoRedirectCoveredRelationsImplicitDeny(t *testing.T) {
	rs := loadRules(t, redirectPolicy(`
  - name: redirect-users
    db_service: appdb
    operations: [READ]
    relations: ["public.users"]
    match_object_resolution: catalog_resolved
    decision: redirect
    redirect:
      relation: public.safe_users
  - name: redirect-orders
    db_service: appdb
    operations: [READ]
    relations: ["public.orders"]
    match_object_resolution: catalog_resolved
    decision: redirect
    redirect:
      relation: public.safe_orders
`))

	stmt := catalogResolvedRead("public", "users")
	stmt.Effects[0].Objects = append(stmt.Effects[0].Objects, effects.ObjectRef{Kind: effects.ObjectTable, Name: "orders"})
	stmt.Effects[0].ResolvedObjects = append(stmt.Effects[0].ResolvedObjects, effects.ResolvedObjectRef{
		Source: effects.ResolvedObjectSourceCatalog,
		Kind:   effects.ResolvedObjectRelation,
		Schema: "public",
		Name:   "orders",
	})

	d := Evaluate(stmt, rs, "appdb")
	if d.Verb != VerbDeny || d.RuleName != "" {
		t.Fatalf("decision = %+v, want implicit deny", d)
	}
	if d.Redirect != nil {
		t.Fatalf("Redirect = %+v, want nil", d.Redirect)
	}
}

func TestEvaluate_ImplicitDenyBeatsRedirect(t *testing.T) {
	rs := loadRules(t, redirectPolicy(`
  - name: redirect-users
    db_service: appdb
    operations: [READ]
    relations: ["public.users"]
    match_object_resolution: catalog_resolved
    decision: redirect
    redirect:
      relation: public.safe_users
`))

	stmt := catalogResolvedRead("public", "users")
	stmt.Effects[0].Objects = append(stmt.Effects[0].Objects, effects.ObjectRef{Kind: effects.ObjectTable, Name: "orders"})
	stmt.Effects[0].ResolvedObjects = append(stmt.Effects[0].ResolvedObjects, effects.ResolvedObjectRef{
		Source: effects.ResolvedObjectSourceCatalog,
		Kind:   effects.ResolvedObjectRelation,
		Schema: "public",
		Name:   "orders",
	})

	d := Evaluate(stmt, rs, "appdb")
	if d.Verb != VerbDeny || d.RuleName != "" {
		t.Fatalf("decision = %+v, want implicit deny", d)
	}
	if d.Redirect != nil {
		t.Fatalf("Redirect = %+v, want nil", d.Redirect)
	}
}

func redirectPolicy(rules string) string {
	return `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
` + rules
}

func catalogResolvedRead(schema, name string) effects.ClassifiedStatement {
	return effects.ClassifiedStatement{Effects: []effects.Effect{{
		Group:      effects.GroupRead,
		Resolution: effects.ResolutionCatalogResolved,
		Objects:    []effects.ObjectRef{{Kind: effects.ObjectTable, Name: name}},
		ResolvedObjects: []effects.ResolvedObjectRef{{
			Source: effects.ResolvedObjectSourceCatalog,
			Kind:   effects.ResolvedObjectRelation,
			Schema: schema,
			Name:   name,
		}},
	}}}
}
