//go:build linux

package postgres

import (
	"testing"

	"github.com/agentsh/agentsh/internal/db/policy"
	rootpolicy "github.com/agentsh/agentsh/internal/policy"
)

// loadRuleSet decodes a YAML policy via the same path the supervisor uses.
// Mirrors the helper in internal/db/policy/decode_test.go.
func loadRuleSet(t *testing.T, src string) *policy.RuleSet {
	t.Helper()
	rp, err := rootpolicy.LoadFromBytes([]byte(src))
	if err != nil {
		t.Fatalf("rootpolicy.LoadFromBytes: %v", err)
	}
	rs, _, err := policy.Decode(rp)
	if err != nil {
		t.Fatalf("policy.Decode: %v", err)
	}
	return rs
}

func TestEvaluateConnect_AllowReturnsAllowDecision(t *testing.T) {
	rs := loadRuleSet(t, `version: 1
name: test
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: db.internal:5432
    tls_mode: terminate_reissue
database_connection_rules:
  - name: allow-alice
    db_service: appdb
    db_user: ["alice"]
    decision: allow
`)
	d := policy.EvaluateConnection(policy.ConnectionInfo{
		Service:        "appdb",
		MatchKind:      policy.MatchConnect,
		DBUser:         "alice",
		ClientIdentity: "uid:1000",
	}, rs)
	if d.Verb != policy.VerbAllow {
		t.Fatalf("Verb = %v, want allow", d.Verb)
	}
}

func TestEvaluateConnect_DenyReturnsDenyDecision(t *testing.T) {
	rs := loadRuleSet(t, `version: 1
name: test
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: db.internal:5432
    tls_mode: terminate_reissue
database_connection_rules:
  - name: deny-bob
    db_service: appdb
    db_user: ["bob"]
    decision: deny
`)
	d := policy.EvaluateConnection(policy.ConnectionInfo{
		Service:        "appdb",
		MatchKind:      policy.MatchConnect,
		DBUser:         "bob",
		ClientIdentity: "uid:1000",
	}, rs)
	if d.Verb != policy.VerbDeny {
		t.Fatalf("Verb = %v, want deny", d.Verb)
	}
}
