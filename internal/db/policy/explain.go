package policy

import "github.com/agentsh/agentsh/internal/db/effects"

type StatementExplanation struct {
	Decision        Decision
	ApplicableRules []string
	Effects         []EffectExplanation
}

type EffectExplanation struct {
	Index         int
	Group         effects.Group
	Subtype       effects.Subtype
	Resolution    effects.Resolution
	Coverage      []ObjectCoverage
	CoveringRules []RuleMatch
	DenyRules     []RuleMatch
}

type ObjectCoverage struct {
	Index           int
	Object          effects.ObjectRef
	ResolvedObject  *effects.ResolvedObjectRef
	Covered         bool
	CoveringRules   []RuleMatch
	UncoveredReason string
}

type RuleMatch struct {
	RuleName string
	Verb     DecisionVerb
	Selector string
}

func ExplainStatement(stmt effects.ClassifiedStatement, rs *RuleSet, svc ServiceID) StatementExplanation {
	if rs == nil {
		return StatementExplanation{Decision: implicitDeny(stmt, 0, "policy not loaded")}
	}
	applicable := rs.statementRulesFor(svc)
	perEffect := make([]effectDecision, len(stmt.Effects))
	effectsOut := make([]EffectExplanation, len(stmt.Effects))
	for i, e := range stmt.Effects {
		perEffect[i], effectsOut[i] = explainEffect(i, e, applicable)
	}
	applicableNames := make([]string, 0, len(applicable))
	for _, r := range applicable {
		applicableNames = append(applicableNames, r.src.Name)
	}
	if len(stmt.Effects) == 0 {
		return StatementExplanation{Decision: implicitDeny(stmt, 0, "no effects on statement"), ApplicableRules: applicableNames}
	}
	return StatementExplanation{
		Decision:        foldEffects(stmt, perEffect),
		ApplicableRules: applicableNames,
		Effects:         effectsOut,
	}
}

func explainEffect(index int, e effects.Effect, applicable []*compiledStatementRule) (effectDecision, EffectExplanation) {
	d := evaluateEffect(e, applicable)
	ex := EffectExplanation{
		Index:      index,
		Group:      e.Group,
		Subtype:    e.Subtype,
		Resolution: e.Resolution,
	}
	if len(e.Objects) == 0 {
		explainNoObjectEffect(e, applicable, &ex)
		return d, ex
	}
	denySeen := map[string]struct{}{}
	for i, obj := range e.Objects {
		cov := ObjectCoverage{Index: i, Object: obj}
		if resolved, ok := resolvedObjectForSlot(e, i); ok {
			r := resolved
			cov.ResolvedObject = &r
		}
		for _, r := range applicable {
			if !ruleMatchesEffectMeta(r, e) {
				continue
			}
			ok, selector := ruleMatchesObjectSlot(r, e, i)
			if !ok {
				continue
			}
			if r.verb == VerbDeny {
				ex.DenyRules = appendRuleMatchUnique(ex.DenyRules, denySeen, RuleMatch{RuleName: r.src.Name, Verb: r.verb, Selector: selector})
				continue
			}
			cov.Covered = true
			cov.CoveringRules = append(cov.CoveringRules, RuleMatch{RuleName: r.src.Name, Verb: r.verb, Selector: selector})
		}
		if !cov.Covered {
			cov.UncoveredReason = "no matching non-deny rule covers object"
		}
		ex.Coverage = append(ex.Coverage, cov)
	}
	return d, ex
}

func explainNoObjectEffect(e effects.Effect, applicable []*compiledStatementRule, ex *EffectExplanation) {
	switch {
	case isResolvedOnlyFunctionEffect(e):
		explainResolvedOnlyFunctionEffect(e, applicable, ex)
	case isObjectlessEffect(e):
		explainObjectlessEffect(e, applicable, ex)
	}
}

func explainResolvedOnlyFunctionEffect(e effects.Effect, applicable []*compiledStatementRule, ex *EffectExplanation) {
	coverSeen := map[string]struct{}{}
	denySeen := map[string]struct{}{}
	for _, r := range applicable {
		if !ruleMatchesEffectMeta(r, e) {
			continue
		}
		selector, ok := resolvedOnlyFunctionRuleSelector(r, e)
		if !ok {
			continue
		}
		match := RuleMatch{RuleName: r.src.Name, Verb: r.verb, Selector: selector}
		if r.verb == VerbDeny {
			ex.DenyRules = appendRuleMatchUnique(ex.DenyRules, denySeen, match)
			continue
		}
		ex.CoveringRules = appendRuleMatchUnique(ex.CoveringRules, coverSeen, match)
	}
}

func resolvedOnlyFunctionRuleSelector(r *compiledStatementRule, e effects.Effect) (string, bool) {
	for _, resolved := range e.ResolvedObjects {
		if !resolvedOnlyFunctionRuleMatches(r, resolved) {
			continue
		}
		if !r.hasObjectSelectors() {
			return "all", true
		}
		if r.functionMatches(resolved) {
			return "functions", true
		}
	}
	return "", false
}

func explainObjectlessEffect(e effects.Effect, applicable []*compiledStatementRule, ex *EffectExplanation) {
	coverSeen := map[string]struct{}{}
	denySeen := map[string]struct{}{}
	for _, r := range applicable {
		if !ruleMatchesEffectMeta(r, e) {
			continue
		}
		if !r.coversAllObjects() {
			continue
		}
		match := RuleMatch{RuleName: r.src.Name, Verb: r.verb, Selector: "all"}
		if r.verb == VerbDeny {
			ex.DenyRules = appendRuleMatchUnique(ex.DenyRules, denySeen, match)
			continue
		}
		ex.CoveringRules = appendRuleMatchUnique(ex.CoveringRules, coverSeen, match)
	}
}

func appendRuleMatchUnique(matches []RuleMatch, seen map[string]struct{}, match RuleMatch) []RuleMatch {
	key := match.RuleName + "\x00" + match.Selector
	if _, ok := seen[key]; ok {
		return matches
	}
	seen[key] = struct{}{}
	return append(matches, match)
}
