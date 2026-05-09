package policy

import "testing"

func TestEvaluate_DenyBeatsAllow(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: r-allow, db_service: appdb, operations: [READ], decision: allow}
  - {name: r-deny,  db_service: appdb, operations: [READ], objects: [pii.*], decision: deny}
`)
	d := Evaluate(tableRead("users", "pii.ssns"), rs, "appdb")
	if d.Verb != VerbDeny {
		t.Fatalf("verb = %v, want deny", d.Verb)
	}
	if d.RuleName != "r-deny" {
		t.Errorf("RuleName = %q, want r-deny", d.RuleName)
	}
}

func TestEvaluate_DenyBeatsApprove(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: appr,  db_service: appdb, operations: [READ], decision: approve}
  - {name: deny,  db_service: appdb, operations: [READ], objects: [pii.*], decision: deny}
`)
	d := Evaluate(tableRead("pii.ssns"), rs, "appdb")
	if d.Verb != VerbDeny {
		t.Fatalf("verb = %v, want deny", d.Verb)
	}
}
