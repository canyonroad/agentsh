package policy

import "testing"

func TestEvaluateConnection_Allow(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_connection_rules:
  - {name: c1, db_service: appdb, decision: allow}
`)
	d := EvaluateConnection(ConnectionInfo{Service: "appdb"}, rs)
	if d.Verb != VerbAllow || d.RuleName != "c1" {
		t.Fatalf("verb=%v rule=%q, want allow/c1", d.Verb, d.RuleName)
	}
	if d.MatchingEffectIndex != -1 {
		t.Errorf("MatchingEffectIndex = %d, want -1", d.MatchingEffectIndex)
	}
}

func TestEvaluateConnection_DenyByUser(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_connection_rules:
  - {name: only-readonly, db_service: appdb, db_user: [readonly], decision: allow}
`)
	d := EvaluateConnection(ConnectionInfo{Service: "appdb", DBUser: "writer"}, rs)
	if d.Verb != VerbDeny || d.RuleName != "" {
		t.Fatalf("verb=%v rule=%q, want implicit deny", d.Verb, d.RuleName)
	}
}

func TestEvaluateConnection_DenyBeatsAllow(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_connection_rules:
  - {name: a, db_service: appdb, decision: allow}
  - {name: d, db_service: appdb, db_user: [evil], decision: deny}
`)
	d := EvaluateConnection(ConnectionInfo{Service: "appdb", DBUser: "evil"}, rs)
	if d.Verb != VerbDeny || d.RuleName != "d" {
		t.Fatalf("verb=%v rule=%q, want deny/d", d.Verb, d.RuleName)
	}
}

func TestEvaluateConnection_CancelKindFiltersByMatchKind(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_connection_rules:
  - {name: connect-allow, db_service: appdb, decision: allow}
  - {name: cancel-allow,  db_service: appdb, match_kind: cancel, decision: allow}
`)
	d := EvaluateConnection(ConnectionInfo{Service: "appdb", MatchKind: MatchCancel}, rs)
	if d.RuleName != "cancel-allow" {
		t.Fatalf("RuleName = %q, want cancel-allow", d.RuleName)
	}
	if d.RuleKind != RuleKindCancel {
		t.Errorf("RuleKind = %v, want cancel", d.RuleKind)
	}
}

func TestEvaluateConnection_ApplicationNameGlob(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_connection_rules:
  - {name: psql-only, db_service: appdb, application_name: "psql*", decision: allow}
`)
	d := EvaluateConnection(ConnectionInfo{Service: "appdb", ApplicationName: "psql 16"}, rs)
	if d.Verb != VerbAllow {
		t.Errorf("psql 16 should match psql*: verb=%v", d.Verb)
	}
	d = EvaluateConnection(ConnectionInfo{Service: "appdb", ApplicationName: "myapp"}, rs)
	if d.Verb != VerbDeny {
		t.Errorf("myapp should NOT match: verb=%v", d.Verb)
	}
}
