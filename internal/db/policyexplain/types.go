package policyexplain

import (
	"github.com/agentsh/agentsh/internal/db/effects"
	dbpolicy "github.com/agentsh/agentsh/internal/db/policy"
)

type Options struct {
	SQL            string
	Service        dbpolicy.ServiceID
	Dialect        string
	SearchPath     []string
	TempTables     []string
	CatalogFixture string
}

type Report struct {
	Service       string            `json:"service"`
	Dialect       string            `json:"dialect"`
	CatalogSource string            `json:"catalog_source"`
	Statements    []StatementReport `json:"statements"`
	Warnings      []WarningReport   `json:"warnings,omitempty"`
}

type StatementReport struct {
	Index         int            `json:"index"`
	RawVerb       string         `json:"raw_verb,omitempty"`
	ParserBackend string         `json:"parser_backend,omitempty"`
	Effects       []EffectReport `json:"effects"`
	Decision      DecisionReport `json:"decision"`
	Error         string         `json:"error,omitempty"`
}

type EffectReport struct {
	Index           int                         `json:"index"`
	Operation       string                      `json:"operation"`
	Subtype         string                      `json:"subtype,omitempty"`
	Resolution      string                      `json:"resolution"`
	Objects         []effects.ObjectRef         `json:"objects,omitempty"`
	ResolvedObjects []effects.ResolvedObjectRef `json:"resolved_objects,omitempty"`
	Coverage        []CoverageReport            `json:"coverage,omitempty"`
	CoveringRules   []RuleReport                `json:"covering_rules,omitempty"`
	DenyRules       []RuleReport                `json:"deny_rules,omitempty"`
}

type CoverageReport struct {
	Object          string       `json:"object,omitempty"`
	ResolvedObject  string       `json:"resolved_object,omitempty"`
	Covered         bool         `json:"covered"`
	CoveringRules   []RuleReport `json:"covering_rules,omitempty"`
	UncoveredReason string       `json:"uncovered_reason,omitempty"`
	Selector        string       `json:"selector,omitempty"`
}

type RuleReport struct {
	RuleName string `json:"rule_name"`
	Verb     string `json:"verb"`
	Selector string `json:"selector,omitempty"`
}

type DecisionReport struct {
	Verb                string `json:"verb"`
	RuleKind            string `json:"rule_kind,omitempty"`
	RuleName            string `json:"rule_name,omitempty"`
	MatchingEffectIndex int    `json:"matching_effect_index"`
	MatchingEffectGroup string `json:"matching_effect_group,omitempty"`
	Reason              string `json:"reason,omitempty"`
}

type WarningReport struct {
	Rule    string `json:"rule,omitempty"`
	Field   string `json:"field,omitempty"`
	Code    string `json:"code"`
	Message string `json:"message"`
}
