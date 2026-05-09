package policy

import (
	"testing"

	"github.com/agentsh/agentsh/internal/db/effects"
)

func TestEvaluate_MultiEffect_DenyFromAnyEffect(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: read-allow, db_service: appdb, operations: [READ], decision: allow}
`)
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{
		{Group: effects.GroupWrite, Objects: []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "log"}}},
		{Group: effects.GroupRead, Objects: []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "x"}}},
	}}
	d := Evaluate(stmt, rs, "appdb")
	if d.Verb != VerbDeny {
		t.Fatalf("verb = %v, want deny (write effect implicitly denied)", d.Verb)
	}
	// MatchingEffectIndex should point at the denying (write) effect.
	if d.MatchingEffectIndex != 0 {
		t.Errorf("MatchingEffectIndex = %d, want 0", d.MatchingEffectIndex)
	}
}
