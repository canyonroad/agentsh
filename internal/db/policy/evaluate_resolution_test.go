package policy

import (
	"testing"

	"github.com/agentsh/agentsh/internal/db/effects"
)

func TestEvaluate_MatchObjectResolution(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: r, db_service: appdb, operations: [READ], match_object_resolution: qualified_syntactic, decision: allow}
`)
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{
		{Group: effects.GroupRead, Resolution: effects.ResolutionQualified, Objects: []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "users"}}},
	}}
	if d := Evaluate(stmt, rs, "appdb"); d.Verb != VerbAllow {
		t.Errorf("qualified should match: verb=%v", d.Verb)
	}

	stmt.Effects[0].Resolution = effects.ResolutionUnqualified
	if d := Evaluate(stmt, rs, "appdb"); d.Verb != VerbDeny || d.RuleName != "" {
		t.Errorf("unqualified should NOT match qualified rule: verb=%v rule=%q", d.Verb, d.RuleName)
	}
}
