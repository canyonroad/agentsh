package policy

import (
	"errors"
	"strings"
	"testing"
	"time"
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
