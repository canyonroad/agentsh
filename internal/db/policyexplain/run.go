package policyexplain

import (
	"fmt"
	"strings"

	classify_pg "github.com/agentsh/agentsh/internal/db/classify/postgres"
	"github.com/agentsh/agentsh/internal/db/effects"
	dbpolicy "github.com/agentsh/agentsh/internal/db/policy"
)

func Run(rs *dbpolicy.RuleSet, warns []dbpolicy.Warning, opts Options) (Report, error) {
	dialect, ok := classify_pg.ParseDialect(defaultString(opts.Dialect, "postgres"))
	if !ok {
		return Report{}, fmt.Errorf("unknown dialect %q", opts.Dialect)
	}
	searchPath := append([]string(nil), opts.SearchPath...)
	sess := classify_pg.SessionState{
		SearchPath:        searchPath,
		DefaultSearchPath: append([]string(nil), searchPath...),
	}
	if len(opts.TempTables) > 0 {
		sess.TempTables = make(map[string]struct{}, len(opts.TempTables))
		for _, name := range opts.TempTables {
			sess.TempTables[strings.ToLower(strings.TrimSpace(name))] = struct{}{}
		}
	}
	stmts, err := classify_pg.New(dialect).Classify(opts.SQL, sess, classify_pg.Options{})
	if err != nil {
		return Report{}, err
	}
	catalogSource := "none"
	if opts.CatalogFixture != "" {
		fixture, err := LoadCatalogFixture(opts.CatalogFixture)
		if err != nil {
			return Report{}, err
		}
		stmts = resolveStatements(stmts, fixture)
		catalogSource = "fixture"
	}
	report := Report{
		Service:       string(opts.Service),
		Dialect:       dialect.String(),
		CatalogSource: catalogSource,
		Warnings:      warningReports(warns),
	}
	if catalogSource == "none" && rs.UsesCanonicalSelectors(opts.Service) {
		report.Warnings = append(report.Warnings, WarningReport{
			Code:    "catalog_fixture_missing_for_canonical_selector",
			Message: "catalog fixture not supplied; canonical relation and function selectors cannot match offline classification",
		})
	}
	for i, stmt := range stmts {
		report.Statements = append(report.Statements, statementReport(i, stmt, dbpolicy.ExplainStatement(stmt, rs, opts.Service)))
	}
	return report, nil
}

func defaultString(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

func warningReports(warns []dbpolicy.Warning) []WarningReport {
	out := make([]WarningReport, 0, len(warns))
	for _, w := range warns {
		out = append(out, WarningReport{Rule: w.Rule, Field: w.Field, Code: w.Code, Message: w.Message})
	}
	return out
}

func statementReport(index int, stmt effects.ClassifiedStatement, ex dbpolicy.StatementExplanation) StatementReport {
	out := StatementReport{
		Index:         index,
		RawVerb:       stmt.RawVerb,
		ParserBackend: stmt.ParserBackend.String(),
		Decision: DecisionReport{
			Verb:                ex.Decision.Verb.String(),
			RuleKind:            ex.Decision.RuleKind.String(),
			RuleName:            ex.Decision.RuleName,
			MatchingEffectIndex: ex.Decision.MatchingEffectIndex,
			MatchingEffectGroup: ex.Decision.MatchingEffectGroup.String(),
			Reason:              ex.Decision.Reason,
		},
		Error: stmt.Error,
	}
	for _, eff := range ex.Effects {
		out.Effects = append(out.Effects, effectReport(eff, stmt.Effects[eff.Index]))
	}
	return out
}

func effectReport(ex dbpolicy.EffectExplanation, eff effects.Effect) EffectReport {
	out := EffectReport{
		Index:           ex.Index,
		Operation:       ex.Group.String(),
		Resolution:      ex.Resolution.String(),
		Objects:         append([]effects.ObjectRef(nil), eff.Objects...),
		ResolvedObjects: append([]effects.ResolvedObjectRef(nil), eff.ResolvedObjects...),
	}
	if ex.Subtype != effects.SubtypeNone {
		out.Subtype = ex.Subtype.String()
	}
	for _, cov := range ex.Coverage {
		out.Coverage = append(out.Coverage, coverageReport(cov))
	}
	out.CoveringRules = ruleReports(ex.CoveringRules)
	out.DenyRules = ruleReports(ex.DenyRules)
	return out
}

func coverageReport(cov dbpolicy.ObjectCoverage) CoverageReport {
	out := CoverageReport{
		Object:          objectName(cov.Object),
		Covered:         cov.Covered,
		UncoveredReason: cov.UncoveredReason,
	}
	if cov.ResolvedObject != nil {
		out.ResolvedObject = cov.ResolvedObject.CanonicalName()
	}
	for _, r := range cov.CoveringRules {
		out.CoveringRules = append(out.CoveringRules, ruleReport(r))
		if out.Selector == "" {
			out.Selector = r.Selector
		}
	}
	return out
}

func ruleReports(matches []dbpolicy.RuleMatch) []RuleReport {
	out := make([]RuleReport, 0, len(matches))
	for _, r := range matches {
		out = append(out, ruleReport(r))
	}
	return out
}

func ruleReport(match dbpolicy.RuleMatch) RuleReport {
	return RuleReport{
		RuleName: match.RuleName,
		Verb:     match.Verb.String(),
		Selector: match.Selector,
	}
}

func objectName(o effects.ObjectRef) string {
	switch o.Kind {
	case effects.ObjectExternalEndpoint:
		return o.Host
	case effects.ObjectFilesystemPath:
		return o.Path
	case effects.ObjectProgram:
		return o.Argv0
	default:
		if o.Schema == "" {
			return o.Name
		}
		return o.Schema + "." + o.Name
	}
}
