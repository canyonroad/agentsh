package policy

import "testing"

func TestEvaluate_AuditDoesNotCoverUnrelatedObject(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: aud, db_service: appdb, operations: [READ], objects: [customers], decision: audit, acknowledge_audit_on_dangerous: true}
`)
	d := Evaluate(tableRead("customers", "orders"), rs, "appdb")
	if d.Verb != VerbDeny || d.RuleName != "" {
		t.Fatalf("verb = %v, RuleName = %q; want implicit deny (orders uncovered)", d.Verb, d.RuleName)
	}
}
