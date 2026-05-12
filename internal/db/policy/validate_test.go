package policy

import (
	"errors"
	"strings"
	"testing"
	"time"

	rootpolicy "github.com/agentsh/agentsh/internal/policy"
)

// helperValidate runs validate against the decoded shapes; tests construct
// these directly rather than going through Decode so each error code is
// reachable in isolation.
func helperValidate(t *testing.T, svcs map[ServiceID]*DBService, stmt []*StatementRule, conn []*ConnectionRule) ([]Warning, error) {
	t.Helper()
	return validate(svcs, stmt, conn)
}

func TestValidate_NoErrors(t *testing.T) {
	svcs := map[ServiceID]*DBService{
		"appdb": {Name: "appdb", Family: "postgres", Dialect: "postgres",
			Upstream: "db.internal:5432", TLSMode: "terminate_reissue"},
	}
	stmt := []*StatementRule{{Name: "r1", DBService: "appdb", Operations: []string{"READ"}, Decision: "allow"}}
	conn := []*ConnectionRule{{Name: "c1", DBService: "appdb", Decision: "allow"}}
	if _, err := helperValidate(t, svcs, stmt, conn); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestValidate_ServiceTLSModeRequired(t *testing.T) {
	svcs := map[ServiceID]*DBService{"appdb": {Name: "appdb", Family: "postgres", Dialect: "postgres", Upstream: "x:1"}}
	_, err := helperValidate(t, svcs, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "service_tls_mode_required") {
		t.Fatalf("want service_tls_mode_required, got %v", err)
	}
}

func TestValidate_ServiceUnknownTLSMode(t *testing.T) {
	svcs := map[ServiceID]*DBService{"appdb": {Name: "appdb", Family: "postgres", Dialect: "postgres", Upstream: "x:1", TLSMode: "weird"}}
	_, err := helperValidate(t, svcs, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "service_unknown_tls_mode") {
		t.Fatalf("want service_unknown_tls_mode, got %v", err)
	}
}

func TestValidate_ServicePlaintextUnsafeDest(t *testing.T) {
	svcs := map[ServiceID]*DBService{
		"warehouse": {Name: "warehouse", Family: "postgres", Dialect: "postgres",
			Upstream: "warehouse.public.example.com:5432",
			TLSMode:  "terminate_plaintext_upstream"},
	}
	_, err := helperValidate(t, svcs, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "service_plaintext_unsafe_dest") {
		t.Fatalf("want service_plaintext_unsafe_dest, got %v", err)
	}
}

func TestValidate_ServicePlaintextAllowedOnLoopback(t *testing.T) {
	svcs := map[ServiceID]*DBService{
		"local": {Name: "local", Family: "postgres", Dialect: "postgres",
			Upstream: "127.0.0.1:5432", TLSMode: "terminate_plaintext_upstream"},
	}
	if _, err := helperValidate(t, svcs, nil, nil); err != nil {
		t.Fatalf("loopback plaintext should be allowed: %v", err)
	}
}

func TestValidate_RuleServicePassthrough(t *testing.T) {
	svcs := map[ServiceID]*DBService{
		"legacy": {Name: "legacy", Family: "postgres", Dialect: "postgres", Upstream: "x:1", TLSMode: "passthrough"},
	}
	stmt := []*StatementRule{{Name: "r", DBService: "legacy", Operations: []string{"READ"}, Decision: "allow"}}
	_, err := helperValidate(t, svcs, stmt, nil)
	if err == nil || !strings.Contains(err.Error(), "rule_service_passthrough") {
		t.Fatalf("want rule_service_passthrough, got %v", err)
	}
}

func TestValidate_RuleServiceUnknown(t *testing.T) {
	stmt := []*StatementRule{{Name: "r", DBService: "ghost", Operations: []string{"READ"}, Decision: "allow"}}
	_, err := helperValidate(t, nil, stmt, nil)
	if err == nil || !strings.Contains(err.Error(), "rule_service_unknown") {
		t.Fatalf("want rule_service_unknown, got %v", err)
	}
}

func TestValidate_ConnPassthroughFieldUnavailable(t *testing.T) {
	svcs := map[ServiceID]*DBService{
		"legacy": {Name: "legacy", Family: "postgres", Dialect: "postgres", Upstream: "x:1", TLSMode: "passthrough"},
	}
	conn := []*ConnectionRule{{Name: "c", DBService: "legacy", DBUser: []string{"foo"}, Decision: "allow"}}
	_, err := helperValidate(t, svcs, nil, conn)
	if err == nil || !strings.Contains(err.Error(), "conn_passthrough_field_unavailable") {
		t.Fatalf("want conn_passthrough_field_unavailable, got %v", err)
	}
}

func TestValidate_RuleDecisionRedirect(t *testing.T) {
	stmt := []*StatementRule{{Name: "r", Operations: []string{"READ"}, Decision: "redirect"}}
	_, err := helperValidate(t, nil, stmt, nil)
	if err == nil || !strings.Contains(err.Error(), "rule_decision_redirect") {
		t.Fatalf("want rule_decision_redirect, got %v", err)
	}
}

func TestValidate_RuleUnknownSubtype(t *testing.T) {
	stmt := []*StatementRule{{Name: "r", Operations: []string{"session"}, Subtypes: []string{"not_real"}, Decision: "allow"}}
	_, err := helperValidate(t, nil, stmt, nil)
	if err == nil || !strings.Contains(err.Error(), "rule_unknown_subtype") {
		t.Fatalf("want rule_unknown_subtype, got %v", err)
	}
}

func TestValidate_RuleUnknownOperation(t *testing.T) {
	stmt := []*StatementRule{{Name: "r", Operations: []string{"NONSENSE"}, Decision: "allow"}}
	_, err := helperValidate(t, nil, stmt, nil)
	if err == nil || !strings.Contains(err.Error(), "rule_unknown_operation") {
		t.Fatalf("want rule_unknown_operation, got %v", err)
	}
}

func TestValidate_RuleTooBroadAllow(t *testing.T) {
	stmt := []*StatementRule{{Name: "yolo", Operations: []string{"*"}, Decision: "allow"}}
	_, err := helperValidate(t, nil, stmt, nil)
	if err == nil || !strings.Contains(err.Error(), "rule_too_broad_allow") {
		t.Fatalf("want rule_too_broad_allow, got %v", err)
	}
}

func TestValidate_CancelRuleApprove(t *testing.T) {
	conn := []*ConnectionRule{{Name: "c", MatchKind: "cancel", Decision: "approve"}}
	_, err := helperValidate(t, nil, nil, conn)
	if err == nil || !strings.Contains(err.Error(), "cancel_rule_approve") {
		t.Fatalf("want cancel_rule_approve, got %v", err)
	}
}

func TestValidate_ApproveTimeoutExceedsMax(t *testing.T) {
	stmt := []*StatementRule{{Name: "slow", Operations: []string{"READ"}, Decision: "approve", Timeout: 700 * time.Second}}
	_, err := helperValidate(t, nil, stmt, nil)
	if err == nil || !strings.Contains(err.Error(), "approve_timeout_exceeds_max") {
		t.Fatalf("want approve_timeout_exceeds_max, got %v", err)
	}
}

func TestValidate_AllErrorsJoin(t *testing.T) {
	// Two unrelated errors must both surface (errors.Join).
	svcs := map[ServiceID]*DBService{"appdb": {Name: "appdb", Family: "postgres", Dialect: "postgres", Upstream: "x:1"}}
	stmt := []*StatementRule{{Name: "r", DBService: "ghost", Operations: []string{"READ"}, Decision: "allow"}}
	_, err := helperValidate(t, svcs, stmt, nil)
	if err == nil {
		t.Fatal("want error")
	}
	if !strings.Contains(err.Error(), "service_tls_mode_required") || !strings.Contains(err.Error(), "rule_service_unknown") {
		t.Fatalf("expected both error codes joined, got: %v", err)
	}
	// Sanity: errors.Is over the joined error.
	_ = errors.Unwrap(err)
}

func TestValidate_WarnAuditOnDangerous(t *testing.T) {
	stmt := []*StatementRule{{Name: "aud-drop", Operations: []string{"DROP"}, Decision: "audit"}}
	ws, err := helperValidate(t, nil, stmt, nil)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	found := false
	for _, w := range ws {
		if w.Code == "audit_on_dangerous" && w.Rule == "aud-drop" {
			found = true
		}
	}
	if !found {
		t.Errorf("want audit_on_dangerous warning for aud-drop, got %v", ws)
	}
}

func TestValidate_WarnAuditOnDangerous_SilencedByAcknowledgement(t *testing.T) {
	stmt := []*StatementRule{{
		Name: "aud-drop", Operations: []string{"DROP"}, Decision: "audit",
		AcknowledgeAuditOnDangerous: true,
	}}
	ws, err := helperValidate(t, nil, stmt, nil)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	for _, w := range ws {
		if w.Code == "audit_on_dangerous" {
			t.Errorf("acknowledge_audit_on_dangerous: true should silence the warning, got %+v", w)
		}
	}
}

func TestValidate_WarnApproveOnReplication(t *testing.T) {
	conn := []*ConnectionRule{{Name: "rep-appr", MatchKind: "replication", Decision: "approve"}}
	ws, err := helperValidate(t, nil, nil, conn)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	found := false
	for _, w := range ws {
		if w.Code == "approve_on_replication" && w.Rule == "rep-appr" {
			found = true
		}
	}
	if !found {
		t.Errorf("want approve_on_replication warning for rep-appr, got %v", ws)
	}
}

func TestValidate_ApproveTimeoutExceedsMax_ConnectionRule(t *testing.T) {
	conn := []*ConnectionRule{{Name: "slow", Decision: "approve", Timeout: 700 * time.Second}}
	_, err := helperValidate(t, nil, nil, conn)
	if err == nil || !strings.Contains(err.Error(), "approve_timeout_exceeds_max") {
		t.Fatalf("want approve_timeout_exceeds_max for connection rule, got %v", err)
	}
}

func TestValidate_PassthroughInvisibleFieldRule(t *testing.T) {
	tests := []struct {
		name         string
		yaml         string
		wantError    bool
		wantCode     string
		wantContains []string
	}{
		{
			name: "db_user under passthrough rejected",
			yaml: `version: 1
name: test
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: db.internal:5432
    tls_mode: passthrough
database_connection_rules:
  - name: r1
    db_service: appdb
    db_user: ["admin"]
    decision: deny
`,
			wantError: true,
			wantCode:  "conn_passthrough_field_unavailable",
		},
		{
			name: "database under passthrough rejected",
			yaml: `version: 1
name: test
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: db.internal:5432
    tls_mode: passthrough
database_connection_rules:
  - name: r1
    db_service: appdb
    database: prod
    decision: deny
`,
			wantError: true,
			wantCode:  "conn_passthrough_field_unavailable",
		},
		{
			name: "application_name under passthrough rejected",
			yaml: `version: 1
name: test
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: db.internal:5432
    tls_mode: passthrough
database_connection_rules:
  - name: r1
    db_service: appdb
    application_name: psql
    decision: deny
`,
			wantError: true,
			wantCode:  "conn_passthrough_field_unavailable",
		},
		{
			name: "client_identity under passthrough is allowed (visible pre-handshake)",
			yaml: `version: 1
name: test
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: db.internal:5432
    tls_mode: passthrough
database_connection_rules:
  - name: r1
    db_service: appdb
    client_identity: agent
    decision: deny
`,
			wantError: false,
		},
		{
			name: "db_user under terminate_reissue is allowed",
			yaml: `version: 1
name: test
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: db.internal:5432
    tls_mode: terminate_reissue
database_connection_rules:
  - name: r1
    db_service: appdb
    db_user: ["admin"]
    decision: deny
`,
			wantError: false,
		},
		{
			name: "db_user wildcard rule rejected when any service is passthrough",
			yaml: `version: 1
name: test
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: db.internal:5432
    tls_mode: passthrough
  otherdb:
    family: postgres
    dialect: postgres
    upstream: db2.internal:5432
    tls_mode: terminate_reissue
database_connection_rules:
  - name: r1
    db_user: ["admin"]
    decision: deny
`,
			wantError:    true,
			wantContains: []string{"conn_passthrough_field_unavailable", "triggered by service"},
		},
		{
			name: "db_user wildcard rule allowed when no service is passthrough",
			yaml: `version: 1
name: test
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: db.internal:5432
    tls_mode: terminate_reissue
database_connection_rules:
  - name: r1
    db_user: ["admin"]
    decision: deny
`,
			wantError: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rp, err := rootpolicy.LoadFromBytes([]byte(tc.yaml))
			if err != nil {
				t.Fatalf("LoadFromBytes: %v", err)
			}
			_, _, err = Decode(rp)
			gotErr := err != nil
			if gotErr != tc.wantError {
				t.Fatalf("Decode error = %v, wantError = %v", err, tc.wantError)
			}
			if tc.wantCode != "" && !strings.Contains(err.Error(), tc.wantCode) {
				t.Fatalf("Decode error = %q, wantCode contains %q", err.Error(), tc.wantCode)
			}
			for _, want := range tc.wantContains {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("Decode error = %q, wantContains %q", err.Error(), want)
				}
			}
		})
	}
}

func TestValidate_GlobCompileViaDecode(t *testing.T) {
	src := `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: r, db_service: appdb, objects: ["["], operations: [READ], decision: allow}
`
	p, err := rootpolicy.LoadFromBytes([]byte(src))
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	_, _, err = Decode(p)
	if err == nil || !strings.Contains(err.Error(), "glob_compile") {
		t.Fatalf("want glob_compile error, got %v", err)
	}
}

func TestValidate_MessageTemplateParseViaDecode(t *testing.T) {
	src := `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: r, db_service: appdb, operations: [READ], decision: deny, message: "{{.Unclosed"}
`
	p, err := rootpolicy.LoadFromBytes([]byte(src))
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	_, _, err = Decode(p)
	if err == nil || !strings.Contains(err.Error(), "message_template_parse") {
		t.Fatalf("want message_template_parse error, got %v", err)
	}
}

func TestValidate_DenyModeInTx_AcceptedOnDenyRule(t *testing.T) {
	src := `version: 1
name: test
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: "127.0.0.1:5432", tls_mode: terminate_reissue}
database_rules:
  - name: block-delete
    db_service: appdb
    operations: [delete]
    decision: deny
    deny_mode_in_tx: rollback_then_continue
`
	p, err := rootpolicy.LoadFromBytes([]byte(src))
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	rs, _, err := Decode(p)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if rs == nil {
		t.Fatal("rs nil")
	}
}

func TestValidate_DenyModeInTx_AcceptedTerminate(t *testing.T) {
	src := `version: 1
name: test
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: "127.0.0.1:5432", tls_mode: terminate_reissue}
database_rules:
  - name: block-delete
    db_service: appdb
    operations: [delete]
    decision: deny
    deny_mode_in_tx: terminate
`
	p, err := rootpolicy.LoadFromBytes([]byte(src))
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	if _, _, err := Decode(p); err != nil {
		t.Fatalf("Decode: %v", err)
	}
}

func TestValidate_DenyModeInTx_RejectedOnAllowRule(t *testing.T) {
	src := `version: 1
name: test
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: "127.0.0.1:5432", tls_mode: terminate_reissue}
database_rules:
  - name: allow-read
    db_service: appdb
    operations: [read]
    decision: allow
    deny_mode_in_tx: rollback_then_continue
`
	p, err := rootpolicy.LoadFromBytes([]byte(src))
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	_, _, err = Decode(p)
	if err == nil {
		t.Fatal("expected error; got nil")
	}
	if !strings.Contains(err.Error(), "deny_mode_in_tx") {
		t.Fatalf("unexpected err: %v", err)
	}
}

func TestValidate_DenyModeInTx_RejectedUnknownValue(t *testing.T) {
	src := `version: 1
name: test
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: "127.0.0.1:5432", tls_mode: terminate_reissue}
database_rules:
  - name: block-delete
    db_service: appdb
    operations: [delete]
    decision: deny
    deny_mode_in_tx: banana
`
	p, err := rootpolicy.LoadFromBytes([]byte(src))
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	_, _, err = Decode(p)
	if err == nil {
		t.Fatal("expected error; got nil")
	}
	if !strings.Contains(err.Error(), "deny_mode_in_tx") {
		t.Fatalf("unexpected err: %v", err)
	}
}
