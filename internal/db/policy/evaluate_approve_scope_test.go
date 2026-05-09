package policy

import "testing"

func TestEvaluate_ApproveDoesNotExtendCoverage(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: app, db_service: appdb, operations: [READ], objects: [needs_approval], decision: approve}
`)
	d := Evaluate(tableRead("uncovered", "needs_approval"), rs, "appdb")
	if d.Verb != VerbDeny || d.RuleName != "" {
		t.Fatalf("verb = %v, RuleName = %q; want implicit deny (uncovered uncovered)", d.Verb, d.RuleName)
	}
}

func TestEvaluate_ApproveAndAllowCombineToApprove(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: allow-x, db_service: appdb, operations: [READ], objects: [allowed], decision: allow}
  - {name: appr-y, db_service: appdb, operations: [READ], objects: [needs_approval], decision: approve}
`)
	d := Evaluate(tableRead("allowed", "needs_approval"), rs, "appdb")
	if d.Verb != VerbApprove {
		t.Fatalf("verb = %v, want approve (most-restrictive of allow+approve)", d.Verb)
	}
	if d.Approval == nil || len(d.Approval.ContributingApproveRules) != 1 || d.Approval.ContributingApproveRules[0] != "appr-y" {
		t.Errorf("ContributingApproveRules = %v, want [appr-y]", d.Approval)
	}
}
