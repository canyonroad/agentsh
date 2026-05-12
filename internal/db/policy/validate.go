package policy

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/db/effects"
)

const approveTimeoutMax = 600 * time.Second

// validate checks decoded shapes against §9.4. It returns warnings (load
// proceeds) plus a joined error containing every fatal issue found, in source
// order: services first, then statement rules, then connection rules.
func validate(svcs map[ServiceID]*DBService, stmt []*StatementRule, conn []*ConnectionRule) ([]Warning, error) {
	var errs []error
	var warns []Warning

	for _, s := range svcs {
		errs = append(errs, validateService(s)...)
	}
	for _, r := range stmt {
		es, ws := validateStatementRule(r, svcs)
		errs = append(errs, es...)
		warns = append(warns, ws...)
	}
	for _, r := range conn {
		es, ws := validateConnectionRule(r, svcs)
		errs = append(errs, es...)
		warns = append(warns, ws...)
	}

	if len(errs) == 0 {
		return warns, nil
	}
	return warns, errors.Join(errs...)
}

func validateService(s *DBService) []error {
	var errs []error
	switch s.TLSMode {
	case "":
		errs = append(errs, fmt.Errorf("service_tls_mode_required: db_services[%q]: tls_mode is required", s.Name))
	case "passthrough", "terminate_reissue", "terminate_plaintext_upstream":
		// ok
	default:
		errs = append(errs, fmt.Errorf("service_unknown_tls_mode: db_services[%q]: unknown tls_mode %q", s.Name, s.TLSMode))
	}
	if s.TLSMode == "terminate_plaintext_upstream" && !s.TrustedNetwork {
		host := upstreamHost(s.Upstream)
		if !isLoopbackOrPrivate(host) {
			errs = append(errs, fmt.Errorf("service_plaintext_unsafe_dest: db_services[%q]: terminate_plaintext_upstream to %q requires trusted_network: true", s.Name, host))
		}
	}
	return errs
}

func validateStatementRule(r *StatementRule, svcs map[ServiceID]*DBService) ([]error, []Warning) {
	var errs []error
	var warns []Warning

	// db_service reference checks.
	if r.DBService != "" {
		svc, ok := svcs[ServiceID(r.DBService)]
		switch {
		case !ok:
			errs = append(errs, fmt.Errorf("rule_service_unknown: database_rules[%q]: db_service %q does not exist", r.Name, r.DBService))
		case svc.TLSMode == "passthrough":
			errs = append(errs, fmt.Errorf("rule_service_passthrough: database_rules[%q]: db_service %q is passthrough; statement rules unavailable", r.Name, r.DBService))
		}
	}

	// decision verb.
	switch r.Decision {
	case "allow", "deny", "approve", "audit":
		// ok
	case "redirect":
		errs = append(errs, fmt.Errorf("rule_decision_redirect: database_rules[%q]: redirect is Phase 2", r.Name))
	default:
		errs = append(errs, fmt.Errorf("rule_unknown_decision: database_rules[%q]: unknown decision %q", r.Name, r.Decision))
	}

	// operations / subtypes / match_object_resolution.
	if len(r.Operations) == 0 {
		errs = append(errs, fmt.Errorf("rule_operations_required: database_rules[%q]: operations is required", r.Name))
	}
	groups := map[effects.Group]struct{}{}
	for _, op := range r.Operations {
		gs, ok := effects.ExpandAlias(op)
		if !ok {
			errs = append(errs, fmt.Errorf("rule_unknown_operation: database_rules[%q]: unknown operations token %q", r.Name, op))
			continue
		}
		for _, g := range gs {
			groups[g] = struct{}{}
		}
	}
	for _, st := range r.Subtypes {
		if _, ok := effects.ParseSubtype(st); !ok {
			errs = append(errs, fmt.Errorf("rule_unknown_subtype: database_rules[%q]: unknown subtypes token %q", r.Name, st))
		}
	}
	if r.MatchObjectResolution != "" && r.MatchObjectResolution != "*" {
		if _, ok := effects.ParseResolution(r.MatchObjectResolution); !ok {
			errs = append(errs, fmt.Errorf("rule_unknown_resolution: database_rules[%q]: unknown match_object_resolution %q", r.Name, r.MatchObjectResolution))
		}
	}

	// approve timeout.
	if r.Decision == "approve" && r.Timeout > approveTimeoutMax {
		errs = append(errs, fmt.Errorf("approve_timeout_exceeds_max: database_rules[%q]: timeout %s exceeds %s", r.Name, r.Timeout, approveTimeoutMax))
	}

	// rule_too_broad_allow.
	if r.Decision == "allow" && r.DBService == "" && r.DBFamily == "" {
		hasStar := false
		for _, op := range r.Operations {
			if op == "*" {
				hasStar = true
				break
			}
		}
		if hasStar {
			errs = append(errs, fmt.Errorf("rule_too_broad_allow: database_rules[%q]: refusing to allow operations:[\"*\"] without db_service or db_family scope", r.Name))
		}
	}

	// audit-on-dangerous warning.
	if r.Decision == "audit" && !r.AcknowledgeAuditOnDangerous {
		if hasHighRisk(groups) {
			warns = append(warns, Warning{
				Rule:    r.Name,
				Field:   "decision",
				Code:    "audit_on_dangerous",
				Message: fmt.Sprintf("rule %q audits operations of risk tier >= high; set acknowledge_audit_on_dangerous: true to silence", r.Name),
			})
		}
	}

	// deny_mode_in_tx is only valid on deny rules. §14.3/§14.4.
	if r.DenyModeInTx != "" {
		if r.Decision != "deny" {
			errs = append(errs, fmt.Errorf("rule_deny_mode_in_tx_not_deny: database_rules[%q]: deny_mode_in_tx is only valid on deny rules", r.Name))
		} else {
			switch r.DenyModeInTx {
			case "terminate", "rollback_then_continue":
				// ok
			default:
				errs = append(errs, fmt.Errorf("rule_deny_mode_in_tx_unknown: database_rules[%q]: deny_mode_in_tx %q: must be one of \"terminate\" or \"rollback_then_continue\"", r.Name, r.DenyModeInTx))
			}
		}
	}

	return errs, warns
}

func validateConnectionRule(r *ConnectionRule, svcs map[ServiceID]*DBService) ([]error, []Warning) {
	var errs []error
	var warns []Warning

	mk := r.MatchKind
	if mk == "" {
		mk = "connect"
	}

	// service ref + passthrough field checks.
	var svc *DBService
	if r.DBService != "" {
		s, ok := svcs[ServiceID(r.DBService)]
		if !ok {
			errs = append(errs, fmt.Errorf("rule_service_unknown: database_connection_rules[%q]: db_service %q does not exist", r.Name, r.DBService))
		} else {
			svc = s
		}
	}
	if svc != nil {
		// Named service: check only that specific service.
		if err := validateConnectionRuleVsService(r, svc); err != nil {
			errs = append(errs, err)
		}
	} else if r.DBService == "" {
		// Wildcard rule (no db_service): reject if any passthrough service exists
		// and the rule uses invisible fields — the rule can never fire there.
		for _, s := range svcs {
			if err := validateConnectionRuleVsService(r, s); err != nil {
				errs = append(errs, fmt.Errorf("%w (triggered by service %q)", err, s.Name))
				break
			}
		}
	}

	// match_kind sanity.
	switch mk {
	case "connect", "cancel", "replication":
		// ok
	default:
		errs = append(errs, fmt.Errorf("conn_unknown_match_kind: database_connection_rules[%q]: unknown match_kind %q", r.Name, r.MatchKind))
	}

	// decision verb.
	switch r.Decision {
	case "allow", "deny", "approve", "audit":
		// ok
	case "redirect":
		errs = append(errs, fmt.Errorf("rule_decision_redirect: database_connection_rules[%q]: redirect is Phase 2", r.Name))
	default:
		errs = append(errs, fmt.Errorf("rule_unknown_decision: database_connection_rules[%q]: unknown decision %q", r.Name, r.Decision))
	}

	// cancel + approve forbidden (R19).
	if mk == "cancel" && r.Decision == "approve" {
		errs = append(errs, fmt.Errorf("cancel_rule_approve: database_connection_rules[%q]: approve on match_kind: cancel is invalid (cancel is real-time; cannot be held)", r.Name))
	}

	// approve timeout.
	if r.Decision == "approve" && r.Timeout > approveTimeoutMax {
		errs = append(errs, fmt.Errorf("approve_timeout_exceeds_max: database_connection_rules[%q]: timeout %s exceeds %s", r.Name, r.Timeout, approveTimeoutMax))
	}

	// approve-on-replication warning.
	if mk == "replication" && r.Decision == "approve" {
		warns = append(warns, Warning{
			Rule:    r.Name,
			Field:   "decision",
			Code:    "approve_on_replication",
			Message: fmt.Sprintf("rule %q approves a match_kind: replication connection; replication is default-deny per §11.1", r.Name),
		})
	}

	return errs, warns
}

// validateConnectionRuleVsService returns a non-nil error if the rule matches
// a field that is invisible under the service's tls_mode.
// Per spec §13.2: db_user, database, application_name are not visible under
// tls_mode: passthrough (they are sent in the StartupMessage after TLS
// negotiation). client_identity and SNI are visible pre-handshake and remain
// valid under all tls_mode values.
func validateConnectionRuleVsService(r *ConnectionRule, svc *DBService) error {
	if svc.TLSMode != "passthrough" {
		return nil
	}
	if len(r.DBUser) > 0 {
		return fmt.Errorf("conn_passthrough_field_unavailable: database_connection_rules[%q]: db_user/database/application_name not visible under passthrough", r.Name)
	}
	if r.Database != "" {
		return fmt.Errorf("conn_passthrough_field_unavailable: database_connection_rules[%q]: db_user/database/application_name not visible under passthrough", r.Name)
	}
	if r.ApplicationName != "" {
		return fmt.Errorf("conn_passthrough_field_unavailable: database_connection_rules[%q]: db_user/database/application_name not visible under passthrough", r.Name)
	}
	return nil
}

// hasHighRisk reports whether the alias-expanded group set includes any
// risk tier >= high (per §9.4 R13).
func hasHighRisk(groups map[effects.Group]struct{}) bool {
	for g := range groups {
		switch g.RiskTier() {
		case effects.High, effects.Critical:
			return true
		}
	}
	return false
}

// upstreamHost extracts the host portion of "host:port"; returns the input
// unchanged on parse failure.
func upstreamHost(upstream string) string {
	host, _, err := net.SplitHostPort(upstream)
	if err != nil {
		return upstream
	}
	return host
}

// isLoopbackOrPrivate reports whether host is a loopback address, a private
// (RFC1918 / ULA) IP, or the literal "localhost".
func isLoopbackOrPrivate(host string) bool {
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// Hostnames other than "localhost" are not assumed safe.
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate()
}
