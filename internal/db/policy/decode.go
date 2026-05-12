package policy

import (
	"bytes"
	"fmt"
	"sort"

	"gopkg.in/yaml.v3"

	classifybuiltins "github.com/agentsh/agentsh/internal/db/classify/postgres/builtins"
	"github.com/agentsh/agentsh/internal/db/service"
	rootpolicy "github.com/agentsh/agentsh/internal/policy"
)

// Decode turns a parsed *internal/policy.Policy into a fully validated and
// compiled *RuleSet. It performs three phases per the design doc §5:
//
//   A. Decode each yaml.Node (db_services, database_rules,
//      database_connection_rules) into typed shapes with KnownFields(true).
//   B. Validate the typed shapes (§9.4 errors + warnings).
//   C. Compile validated rules into the evaluator-ready *RuleSet.
//
// Decode returns (rs, warnings, nil) on success. On error, warnings collected
// up to the point of failure are returned alongside the error.
func Decode(p *rootpolicy.Policy) (*RuleSet, []Warning, error) {
	if p == nil {
		return nil, nil, fmt.Errorf("policy is nil")
	}

	// Phase A.
	svcs, err := decodeServices(p.DBServices)
	if err != nil {
		return nil, nil, err
	}
	stmtRules, err := decodeStatementRules(p.DatabaseRules)
	if err != nil {
		return nil, nil, err
	}
	connRules, err := decodeConnectionRules(p.DatabaseConnectionRules)
	if err != nil {
		return nil, nil, err
	}
	red, err := decodeRedaction(p)
	if err != nil {
		return nil, nil, err
	}
	unavoid, err := decodeUnavoidability(p)
	if err != nil {
		return nil, nil, err
	}

	// Phase B.
	warns, err := validate(svcs, stmtRules, connRules)
	if err != nil {
		return nil, warns, err
	}

	// Phase C.
	rs := &RuleSet{services: svcs, redaction: red, unavoidability: unavoid}
	for _, r := range stmtRules {
		c, err := compileStatementRule(r)
		if err != nil {
			return nil, warns, err
		}
		rs.statement = append(rs.statement, c)
	}
	for _, r := range connRules {
		c, err := compileConnectionRule(r)
		if err != nil {
			return nil, warns, err
		}
		rs.connection = append(rs.connection, c)
	}
	return rs, warns, nil
}

func decodeServices(n yaml.Node) (map[ServiceID]*DBService, error) {
	if n.IsZero() {
		return map[ServiceID]*DBService{}, nil
	}
	raw := map[string]*DBService{}
	if err := strictDecode(n, &raw); err != nil {
		return nil, fmt.Errorf("decode db_services: %w", err)
	}
	out := make(map[ServiceID]*DBService, len(raw))
	for name, svc := range raw {
		svc.Name = name
		out[ServiceID(name)] = svc
	}
	return out, nil
}

func decodeStatementRules(n yaml.Node) ([]*StatementRule, error) {
	if n.IsZero() {
		return nil, nil
	}
	var rules []*StatementRule
	if err := strictDecode(n, &rules); err != nil {
		return nil, fmt.Errorf("decode database_rules: %w", err)
	}
	return rules, nil
}

func decodeConnectionRules(n yaml.Node) ([]*ConnectionRule, error) {
	if n.IsZero() {
		return nil, nil
	}
	var rules []*ConnectionRule
	if err := strictDecode(n, &rules); err != nil {
		return nil, fmt.Errorf("decode database_connection_rules: %w", err)
	}
	return rules, nil
}

// redactionYAML is the on-disk shape of the policies.db block. Only the
// redaction and unavoidability fields are decoded here; the rest of the
// policies block is owned by other packages.
type redactionYAML struct {
	LogStatements                 string   `yaml:"log_statements,omitempty"`
	ApprovalStatementPreview      string   `yaml:"approval_statement_preview,omitempty"`
	ApprovalStatementPreviewChars int      `yaml:"approval_statement_preview_chars,omitempty"`
	Unavoidability                string   `yaml:"unavoidability,omitempty"`
	EscalateUnknownFunctions      bool     `yaml:"escalate_unknown_functions"`
	SafeFunctionAllowlist         []string `yaml:"safe_function_allowlist"`
}

// dbPoliciesWrapper is the on-disk shape of the policies block as far as
// internal/db/policy cares — only the db sub-block is owned here.
type dbPoliciesWrapper struct {
	DB redactionYAML `yaml:"db,omitempty"`
}

// decodeRedaction reads the policies.db sub-block. Defaults: LogStatements=
// parameters_redacted, ApprovalStatementPreview=parameters_redacted (YAML
// alias "redacted"), ApprovalStatementChars=200.
func decodeRedaction(p *rootpolicy.Policy) (RedactionConfig, error) {
	out := RedactionConfig{
		LogStatements:            RedactParametersRedacted,
		ApprovalStatementPreview: RedactParametersRedacted,
		ApprovalStatementChars:   200,
	}
	if p.Policies.IsZero() {
		return out, nil
	}
	var w dbPoliciesWrapper
	if err := strictDecode(p.Policies, &w); err != nil {
		return out, fmt.Errorf("decode policies.db: %w", err)
	}
	rb := w.DB
	if rb.LogStatements != "" {
		t, ok := ParseRedactionTier(rb.LogStatements)
		if !ok {
			return out, fmt.Errorf("redaction_unknown_log_statements: %q", rb.LogStatements)
		}
		out.LogStatements = t
	}
	if rb.ApprovalStatementPreview != "" {
		t, ok := parseApprovalPreviewTier(rb.ApprovalStatementPreview)
		if !ok {
			return out, fmt.Errorf("redaction_unknown_approval_preview: %q", rb.ApprovalStatementPreview)
		}
		out.ApprovalStatementPreview = t
	}
	if rb.ApprovalStatementPreviewChars > 0 {
		out.ApprovalStatementChars = rb.ApprovalStatementPreviewChars
	}
	out.EscalateUnknownFunctions = rb.EscalateUnknownFunctions
	if len(rb.SafeFunctionAllowlist) > 0 {
		out.SafeFunctionAllowlist = append([]string(nil), rb.SafeFunctionAllowlist...)
	} else if out.EscalateUnknownFunctions {
		out.SafeFunctionAllowlist = defaultAllowlistKeys()
	}
	return out, nil
}

// defaultAllowlistKeys returns the builtin seed list as a sorted []string.
// Sorting is deterministic and makes test assertions order-stable.
func defaultAllowlistKeys() []string {
	m := classifybuiltins.DefaultSafeFunctionAllowlist()
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// decodeUnavoidability reads policies.db.unavoidability. Default: UnavoidabilityOff.
// Unknown values are an error.
func decodeUnavoidability(p *rootpolicy.Policy) (service.Unavoidability, error) {
	if p.Policies.IsZero() {
		return service.UnavoidabilityOff, nil
	}
	var w dbPoliciesWrapper
	if err := strictDecode(p.Policies, &w); err != nil {
		return service.UnavoidabilityOff, fmt.Errorf("decode policies.db: %w", err)
	}
	if w.DB.Unavoidability == "" {
		return service.UnavoidabilityOff, nil
	}
	u, ok := service.ParseUnavoidability(w.DB.Unavoidability)
	if !ok {
		return service.UnavoidabilityOff, fmt.Errorf("unknown policies.db.unavoidability: %q", w.DB.Unavoidability)
	}
	return u, nil
}

// parseApprovalPreviewTier handles the §10.3 alias: in approval_statement_preview,
// the value "redacted" maps to RedactParametersRedacted. (LogStatements uses
// the canonical "parameters_redacted" name only.)
func parseApprovalPreviewTier(s string) (RedactionTier, bool) {
	if s == "redacted" {
		return RedactParametersRedacted, true
	}
	return ParseRedactionTier(s)
}

// strictDecode round-trips a yaml.Node through a strict decoder so unknown
// fields fail to load. yaml.Node.Decode does not respect KnownFields by
// default; this re-emits the node and decodes the bytes with the strict flag.
func strictDecode(n yaml.Node, out any) error {
	bs, err := yaml.Marshal(&n)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(bytes.NewReader(bs))
	dec.KnownFields(true)
	return dec.Decode(out)
}
