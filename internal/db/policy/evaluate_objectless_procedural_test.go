package policy

import (
	"testing"

	"github.com/agentsh/agentsh/internal/db/effects"
)

// TestEvaluate_ObjectlessFunctionCallProtocol_Reachable verifies that an
// Effect with Group==GroupProcedural and Subtype==SubtypeFunctionCallProtocol
// (the Postgres 'F' FunctionCall frame, which carries only an OID and has no
// resolvable object name) is reachable through the objectless coverage path
// rather than falling through to implicit deny.
//
// This pins the isObjectlessEffect whitelist introduced in Task 9: FunctionCall
// opt-in must be achievable via a procedural allow rule with no objects clause.
func TestEvaluate_ObjectlessFunctionCallProtocol_Reachable(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: allow-funccall, db_service: appdb, operations: [procedural], decision: allow}
`)
	oid := int32(12345)
	stmt := effects.ClassifiedStatement{
		Effects: []effects.Effect{
			{
				Group:       effects.GroupProcedural,
				Subtype:     effects.SubtypeFunctionCallProtocol,
				Objects:     nil,
				Resolution:  effects.ResolutionQualified,
				FunctionOID: &oid,
			},
		},
	}
	d := Evaluate(stmt, rs, "appdb")
	if d.Verb != VerbAllow {
		t.Fatalf("verb = %v, want allow; FunctionCallProtocol effect must be reachable via objectless coverage (RuleName=%q, Reason=%q)",
			d.Verb, d.RuleName, d.Reason)
	}
	if d.RuleName != "allow-funccall" {
		t.Errorf("RuleName = %q, want \"allow-funccall\"", d.RuleName)
	}
}

// TestEvaluate_ObjectlessProceduralEscalation_FailsClosed verifies that a
// SQL-escalated procedural effect (Group==GroupProcedural, Subtype==SubtypeNone)
// with no Objects is NOT reachable through the objectless coverage path — it
// must fall through to implicit deny (fail-closed escalation posture).
//
// This is the mirror of TestEvaluate_ObjectlessFunctionCallProtocol_Reachable:
// the isObjectlessEffect whitelist must remain narrow so that arbitrary
// objectless procedural effects (e.g. an unresolved CALL or SQL-escalated
// unknown function) do not inadvertently inherit opt-in allow rules.
func TestEvaluate_ObjectlessProceduralEscalation_FailsClosed(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: allow-funccall, db_service: appdb, operations: [procedural], decision: allow}
`)
	stmt := effects.ClassifiedStatement{
		Effects: []effects.Effect{
			{
				Group:      effects.GroupProcedural,
				Subtype:    effects.SubtypeNone, // no subtype — SQL-escalated unknown function
				Objects:    nil,
				Resolution: effects.ResolutionQualified,
			},
		},
	}
	d := Evaluate(stmt, rs, "appdb")
	if d.Verb != VerbDeny {
		t.Fatalf("verb = %v, want deny; SQL-escalated objectless procedural must fail closed (RuleName=%q)",
			d.Verb, d.RuleName)
	}
	if d.RuleName != "" {
		t.Errorf("RuleName = %q, want \"\" for implicit deny", d.RuleName)
	}
}
