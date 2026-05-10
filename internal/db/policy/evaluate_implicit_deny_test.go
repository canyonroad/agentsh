package policy

import (
	"testing"

	"github.com/agentsh/agentsh/internal/db/effects"
)

func TestEvaluate_ImplicitDenyOnUncoveredObject(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: read-users, db_service: appdb, operations: [READ], objects: [users], decision: allow}
`)
	d := Evaluate(tableRead("users", "uncovered_table"), rs, "appdb")
	if d.Verb != VerbDeny {
		t.Fatalf("verb = %v, want deny", d.Verb)
	}
	if d.RuleName != "" {
		t.Errorf("RuleName = %q, want \"\" for implicit deny", d.RuleName)
	}
}

func TestEvaluate_ImplicitDenyWhenNoRules(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
`)
	d := Evaluate(tableRead("users"), rs, "appdb")
	if d.Verb != VerbDeny || d.RuleName != "" {
		t.Fatalf("verb = %v, RuleName = %q; want implicit deny", d.Verb, d.RuleName)
	}
}

func TestEvaluate_EffectWithNoObjectsImplicitDeny(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: read-all, db_service: appdb, operations: [READ], decision: allow}
`)
	// Effect with nil Objects must not panic; should be implicit-deny.
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{
		{Group: effects.GroupRead, Objects: nil, Resolution: effects.ResolutionQualified},
	}}
	d := Evaluate(stmt, rs, "appdb")
	if d.Verb != VerbDeny || d.RuleName != "" {
		t.Fatalf("verb=%v rule=%q, want implicit deny", d.Verb, d.RuleName)
	}
}

func TestEvaluate_NilRuleSetImplicitDeny(t *testing.T) {
	d := Evaluate(tableRead("users"), nil, "appdb")
	if d.Verb != VerbDeny || d.RuleName != "" {
		t.Fatalf("verb=%v rule=%q, want implicit deny on nil rs", d.Verb, d.RuleName)
	}
}
