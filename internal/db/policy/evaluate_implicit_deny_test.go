package policy

import "testing"

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
