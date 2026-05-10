package policy

import (
	"testing"

	"github.com/agentsh/agentsh/internal/db/effects"
	rootpolicy "github.com/agentsh/agentsh/internal/policy"
)

// loadRules is a tiny helper used across evaluator tests.
func loadRules(t *testing.T, src string) *RuleSet {
	t.Helper()
	p, err := rootpolicy.LoadFromBytes([]byte(src))
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	rs, _, err := Decode(p)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	return rs
}

// tableRead builds a ClassifiedStatement of one read effect with the given object
// names; convenience for repetitive single-effect tests.
func tableRead(names ...string) effects.ClassifiedStatement {
	objs := make([]effects.ObjectRef, len(names))
	for i, n := range names {
		objs[i] = effects.ObjectRef{Kind: effects.ObjectTable, Name: n}
	}
	return effects.ClassifiedStatement{
		Effects: []effects.Effect{{Group: effects.GroupRead, Objects: objs, Resolution: effects.ResolutionQualified}},
	}
}

func TestEvaluate_AllowCoversAllObjectsByDefault(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: read-all, db_service: appdb, operations: [READ], decision: allow}
`)
	d := Evaluate(tableRead("users", "orders"), rs, "appdb")
	if d.Verb != VerbAllow {
		t.Fatalf("verb = %v, want allow", d.Verb)
	}
	if d.RuleName != "read-all" {
		t.Errorf("RuleName = %q", d.RuleName)
	}
}

func TestEvaluate_AllowSpecificObjectsCovers(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: read-pii, db_service: appdb, operations: [READ], objects: [pii.*, "users"], decision: allow}
`)
	d := Evaluate(tableRead("pii.ssns", "users"), rs, "appdb")
	if d.Verb != VerbAllow {
		t.Fatalf("verb = %v, want allow (both objects covered)", d.Verb)
	}
}

func TestEvaluate_AuditCoversObject(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: aud, db_service: appdb, operations: [READ], objects: [customers], decision: audit, acknowledge_audit_on_dangerous: true}
`)
	d := Evaluate(tableRead("customers"), rs, "appdb")
	if d.Verb != VerbAudit {
		t.Fatalf("verb = %v, want audit", d.Verb)
	}
}

func TestEvaluate_ApproveCoversObject(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: app, db_service: appdb, operations: [READ], objects: [needs_approval], decision: approve}
`)
	d := Evaluate(tableRead("needs_approval"), rs, "appdb")
	if d.Verb != VerbApprove {
		t.Fatalf("verb = %v, want approve", d.Verb)
	}
	if d.Approval == nil {
		t.Fatal("Approval nil")
	}
	if d.Approval.Timeout == 0 {
		t.Errorf("Timeout zero (default 60s expected)")
	}
}
