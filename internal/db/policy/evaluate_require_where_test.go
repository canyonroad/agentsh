package policy

import (
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/db/effects"
	rootpolicy "github.com/agentsh/agentsh/internal/policy"
)

func mutationStmt(group effects.Group, hasWhere bool) effects.ClassifiedStatement {
	return effects.ClassifiedStatement{
		RawVerb: "UPDATE",
		Effects: []effects.Effect{{
			Group:      group,
			Objects:    []effects.ObjectRef{{Kind: effects.ObjectTable, Schema: "public", Name: "users"}},
			Resolution: effects.ResolutionQualified,
			HasWhere:   hasWhere,
		}},
	}
}

func TestDecode_RequireWhereAccepted(t *testing.T) {
	p, err := rootpolicy.LoadFromBytes([]byte(`version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - name: guarded
    db_service: appdb
    operations: [modify, delete]
    objects: [users]
    require_where: true
    decision: allow
`))
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	rs, _, err := Decode(p)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	rules := rs.AllStatementRules()
	if len(rules) != 1 || !rules[0].RequireWhere {
		t.Fatalf("RequireWhere not decoded: %+v", rules)
	}
}

func TestEvaluate_RequireWhereAllowsMutationWithWhere(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - name: guarded
    db_service: appdb
    operations: [modify]
    objects: [users]
    require_where: true
    decision: allow
`)
	d := Evaluate(mutationStmt(effects.GroupModify, true), rs, "appdb")
	if d.Verb != VerbAllow || d.RuleName != "guarded" {
		t.Fatalf("decision = %+v, want allow by guarded", d)
	}
}

func TestEvaluate_RequireWhereDeniesMutationWithoutWhere(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - name: guarded
    db_service: appdb
    operations: [modify]
    objects: [users]
    require_where: true
    decision: allow
`)
	d := Evaluate(mutationStmt(effects.GroupModify, false), rs, "appdb")
	if d.Verb != VerbDeny || d.RuleName != "" {
		t.Fatalf("decision = %+v, want implicit deny", d)
	}
	if !strings.Contains(d.Reason, "no rule covers") {
		t.Fatalf("Reason = %q, want coverage failure", d.Reason)
	}
}

func TestEvaluate_RequireWhereDoesNotBlockRuleWithoutGuard(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - name: unguarded
    db_service: appdb
    operations: [delete]
    objects: [users]
    decision: allow
`)
	d := Evaluate(mutationStmt(effects.GroupDelete, false), rs, "appdb")
	if d.Verb != VerbAllow || d.RuleName != "unguarded" {
		t.Fatalf("decision = %+v, want allow by unguarded", d)
	}
}
