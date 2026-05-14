// Package policy implements the AgentSH database-access policy evaluator
// per docs/agentsh-db-access-spec.md §9–§10. The package is platform-agnostic
// and produces only data types and pure functions; events, approvals, and
// wire I/O belong to later plans (Plan 04+).
package policy

import (
	"time"

	"github.com/agentsh/agentsh/internal/db/effects"
	"github.com/agentsh/agentsh/internal/db/service"
)

// ServiceID is the operator-supplied identifier of a db_service.
type ServiceID string

// DecisionVerb mirrors the §10.1 verbs. Implicit deny is *not* a separate
// verb; it is encoded as Verb == VerbDeny with RuleName == "" (see §7 of the
// design doc and Decision below).
//
// The numeric ordering (Allow < Audit < Approve < Deny) encodes
// restrictiveness — the evaluator's hot path uses integer comparison
// (max(verb, ...)) to fold per-effect verdicts. Do not reorder these values.
type DecisionVerb uint8

const (
	VerbAllow DecisionVerb = iota
	VerbAudit
	VerbApprove
	VerbDeny
)

func (v DecisionVerb) String() string {
	switch v {
	case VerbAllow:
		return "allow"
	case VerbAudit:
		return "audit"
	case VerbApprove:
		return "approve"
	case VerbDeny:
		return "deny"
	default:
		return ""
	}
}

// RuleKind labels which rule family produced a Decision; surfaced to DBEvent
// as decision.rule_kind in §8.
type RuleKind uint8

const (
	RuleKindStatement RuleKind = iota
	RuleKindConnection
	RuleKindCancel
)

func (k RuleKind) String() string {
	switch k {
	case RuleKindStatement:
		return "statement"
	case RuleKindConnection:
		return "connection"
	case RuleKindCancel:
		return "cancel"
	default:
		return ""
	}
}

// ConnectionMatchKind is the connection rule's match_kind field, used by
// EvaluateConnection.
type ConnectionMatchKind uint8

const (
	MatchConnect ConnectionMatchKind = iota
	MatchCancel
	MatchReplication
)

// DBService is the on-disk shape of a db_services entry per §9.1.
type DBService struct {
	Name                      string `yaml:"-"` // populated from map key
	Family                    string `yaml:"family"`
	Dialect                   string `yaml:"dialect"`
	Upstream                  string `yaml:"upstream"`
	TLSMode                   string `yaml:"tls_mode"`
	AllowFunctionCallProtocol bool   `yaml:"allow_function_call_protocol,omitempty"`
	AllowGSSEncryption        bool   `yaml:"allow_gss_encryption,omitempty"`
	TrustedNetwork            bool   `yaml:"trusted_network,omitempty"`
}

// StatementRule is the on-disk shape of a database_rules entry per §9.2.
type StatementRule struct {
	Name                        string        `yaml:"name"`
	DBService                   string        `yaml:"db_service,omitempty"`
	DBFamily                    string        `yaml:"db_family,omitempty"`
	DBDialect                   string        `yaml:"db_dialect,omitempty"`
	Schemas                     []string      `yaml:"schemas,omitempty"`
	Objects                     []string      `yaml:"objects,omitempty"`
	Relations                   []string      `yaml:"relations,omitempty"`
	Functions                   []string      `yaml:"functions,omitempty"`
	Operations                  []string      `yaml:"operations"`
	Subtypes                    []string      `yaml:"subtypes,omitempty"`
	MatchObjectResolution       string        `yaml:"match_object_resolution,omitempty"`
	Decision                    string        `yaml:"decision"`
	Message                     string        `yaml:"message,omitempty"`
	Timeout                     time.Duration `yaml:"timeout,omitempty"`
	AcknowledgeAuditOnDangerous bool          `yaml:"acknowledge_audit_on_dangerous,omitempty"`
	DenyModeInTx                string        `yaml:"deny_mode_in_tx,omitempty"`
}

// ConnectionRule is the on-disk shape of a database_connection_rules entry per §9.3.
type ConnectionRule struct {
	Name            string        `yaml:"name"`
	DBService       string        `yaml:"db_service,omitempty"`
	MatchKind       string        `yaml:"match_kind,omitempty"`
	DBUser          []string      `yaml:"db_user,omitempty"`
	Database        string        `yaml:"database,omitempty"`
	ApplicationName string        `yaml:"application_name,omitempty"`
	ClientIdentity  string        `yaml:"client_identity,omitempty"`
	Decision        string        `yaml:"decision"`
	Message         string        `yaml:"message,omitempty"`
	Timeout         time.Duration `yaml:"timeout,omitempty"`
}

// ConnectionInfo is the input to EvaluateConnection. Plan 04 populates it
// from StartupMessage parameters (or sentinel zero values under passthrough TLS).
type ConnectionInfo struct {
	Service         ServiceID
	MatchKind       ConnectionMatchKind
	DBUser          string
	Database        string
	ApplicationName string
	ClientIdentity  string
}

// Decision is the output of Evaluate / EvaluateConnection.
//
// Implicit deny (no rule covers an object in some effect) is encoded as
// Verb == VerbDeny with RuleName == "" and Reason == "no rule covers ..." —
// this matches the §8 DBEvent wire schema (decision.verb has only four values)
// while still letting tests assert on the distinction via RuleName.
type Decision struct {
	Verb                   DecisionVerb
	RuleKind               RuleKind
	RuleName               string
	MatchingEffectIndex    int           // -1 for connection-level decisions
	MatchingEffectGroup    effects.Group // GroupUnknown for connection-level decisions
	Reason                 string
	ContributingAuditRules []string // populated only when Verb == VerbApprove
	Approval               *ApprovalRequest
}

// ApprovalRequest carries data Plan 04 needs to spin up the approval flow.
// Plan 02 produces it but does not act on it.
type ApprovalRequest struct {
	Timeout                  time.Duration
	ContributingApproveRules []string
}

// Warning is a non-fatal issue surfaced by Decode. Errors abort load; warnings
// accumulate so operators can fix them at leisure.
type Warning struct {
	Rule    string // rule name, "" for service-level
	Field   string // YAML field, e.g. "decision"
	Code    string // stable identifier for callers / tests
	Message string
	Line    int // yaml.v3 node Line, for IDE-friendly output
}

// RuleSet is the immutable, evaluator-ready policy. Build via Decode.
// Internals are private; callers consume via Evaluate / EvaluateConnection /
// Redaction / Service.
type RuleSet struct {
	services       map[ServiceID]*DBService
	statement      []*compiledStatementRule
	connection     []*compiledConnectionRule
	redaction      RedactionConfig
	unavoidability service.Unavoidability
}

// Redaction returns the policies.db block configuration. Returns the zero
// value when rs is nil so startup code holding a not-yet-loaded *RuleSet
// does not panic.
func (rs *RuleSet) Redaction() RedactionConfig {
	if rs == nil {
		return RedactionConfig{}
	}
	return rs.redaction
}

// Service returns the named db_service definition, if present.
func (rs *RuleSet) Service(id ServiceID) (DBService, bool) {
	if rs == nil {
		return DBService{}, false
	}
	s, ok := rs.services[id]
	if !ok {
		return DBService{}, false
	}
	return *s, true
}

// AllServices returns a copy of every declared db_service. Order is not
// guaranteed; callers that need stable ordering should sort by Name.
// Returns nil when rs is nil.
func (rs *RuleSet) AllServices() []DBService {
	if rs == nil || len(rs.services) == 0 {
		return nil
	}
	out := make([]DBService, 0, len(rs.services))
	for _, s := range rs.services {
		out = append(out, *s)
	}
	return out
}

// AllStatementRules returns a copy of every parsed StatementRule. Order is
// preserved from the source YAML. Returns nil when rs is nil. Used by the
// Extended Query state machine to look up the deny_mode_in_tx field for a
// matched rule.
func (rs *RuleSet) AllStatementRules() []StatementRule {
	if rs == nil || len(rs.statement) == 0 {
		return nil
	}
	out := make([]StatementRule, 0, len(rs.statement))
	for _, cr := range rs.statement {
		if cr.src != nil {
			out = append(out, *cr.src)
		}
	}
	return out
}

// Unavoidability returns the policies.db.unavoidability mode. Returns
// UnavoidabilityOff when rs is nil so startup code holding a not-yet-loaded
// *RuleSet does not panic.
func (rs *RuleSet) Unavoidability() service.Unavoidability {
	if rs == nil {
		return service.UnavoidabilityOff
	}
	return rs.unavoidability
}
