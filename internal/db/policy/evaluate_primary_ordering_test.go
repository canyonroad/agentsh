package policy

import (
	"testing"

	"github.com/agentsh/agentsh/internal/db/effects"
)

// The fold step picks the most-restrictive verb across effects. When two
// effects tie at the same verb (e.g., both deny), the lowest index wins.
// Independently of the fold tiebreak, the input statement may have effects
// in arbitrary order — Evaluate must honor MatchingEffectIndex per the input,
// not re-sort.
func TestEvaluate_FoldTieBreaksOnLowestIndex(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: deny-pii, db_service: appdb, operations: [READ], objects: [pii.*], decision: deny}
  - {name: deny-x,   db_service: appdb, operations: [READ], objects: [x],      decision: deny}
`)
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{
		{Group: effects.GroupRead, Objects: []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "pii.ssns"}}},
		{Group: effects.GroupRead, Objects: []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "x"}}},
	}}
	d := Evaluate(stmt, rs, "appdb")
	if d.Verb != VerbDeny {
		t.Fatalf("verb = %v", d.Verb)
	}
	if d.MatchingEffectIndex != 0 {
		t.Errorf("MatchingEffectIndex = %d, want 0 (lowest index)", d.MatchingEffectIndex)
	}
	if d.RuleName != "deny-pii" {
		t.Errorf("RuleName = %q, want deny-pii", d.RuleName)
	}
}
