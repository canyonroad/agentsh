package policy

import (
	"fmt"

	"github.com/agentsh/agentsh/internal/db/effects"
)

// Evaluate applies the statement-rule policy to a classified statement per
// spec §10.2. Pure function; safe to call concurrently against the same
// *RuleSet (RuleSet is immutable after Decode).
func Evaluate(stmt effects.ClassifiedStatement, rs *RuleSet, svc ServiceID) Decision {
	if rs == nil {
		return implicitDeny(stmt, 0, "policy not loaded")
	}
	applicable := rs.statementRulesFor(svc)
	if len(stmt.Effects) == 0 {
		return implicitDeny(stmt, 0, "no effects on statement")
	}

	perEffect := make([]effectDecision, len(stmt.Effects))
	for i, e := range stmt.Effects {
		perEffect[i] = evaluateEffect(e, applicable)
	}
	return foldEffects(stmt, perEffect)
}

// statementRulesFor returns rules whose service filter matches svc.
func (rs *RuleSet) statementRulesFor(svc ServiceID) []*compiledStatementRule {
	out := make([]*compiledStatementRule, 0, len(rs.statement))
	s := rs.services[svc]
	for _, r := range rs.statement {
		if r.serviceFilter.matches(svc, s) {
			out = append(out, r)
		}
	}
	return out
}

// effectDecision is the per-effect verdict. internalVerb includes
// verbImplicitDeny as a distinct value; foldEffects normalizes to DecisionVerb.
type effectDecision struct {
	verb                internalVerb
	rule                *compiledStatementRule   // primary contributing rule (nil for implicit deny)
	contributingApprove []*compiledStatementRule // contributing approve rules, deduped by name
	contributingAudit   []*compiledStatementRule // contributing audit rules, deduped by name
	uncoveredObject     effects.ObjectRef        // populated when verb == verbImplicitDeny
	denyMatchingObject  effects.ObjectRef        // populated when verb == verbDeny
}

// internalVerb is a package-private enum used by the three-pass algorithm.
// It extends DecisionVerb with a separate verbImplicitDeny value so that
// foldEffects can prefer explicit deny over implicit deny (preserving RuleName
// per the design doc §7 tiebreak note).
//
// Ordering: verbAllow < verbAudit < verbApprove < verbImplicitDeny < verbDeny.
// Higher value = more restrictive. verbImplicitDeny ranks just below verbDeny
// so explicit deny wins ties, giving a non-empty RuleName whenever possible.
type internalVerb uint8

const (
	verbAllow       internalVerb = iota
	verbAudit                    // more restrictive than allow
	verbApprove                  // more restrictive than audit
	verbImplicitDeny             // more restrictive than approve; loses to explicit deny on tie
	verbDeny                     // most restrictive
)

// evaluateEffect runs the three-pass §10.2 algorithm for a single effect.
func evaluateEffect(e effects.Effect, applicable []*compiledStatementRule) effectDecision {
	// An effect with no objects is normally implicit-deny (coverage is per
	// object), preserving the fail-closed posture for object-bearing effects
	// like Read/Write that arrive without resolved objects (parser gap or
	// intentional nil).
	//
	// Exception: groups that *inherently* have no objects — Transaction,
	// Session, Notify — would otherwise be unreachable through the §10.2
	// coverage rules. Treat those as covered by any non-objects-constrained
	// rule whose effect-meta matches.
	if len(e.Objects) == 0 {
		if isObjectlessGroup(e.Group) {
			return evaluateEffectObjectless(e, applicable)
		}
		return effectDecision{verb: verbImplicitDeny}
	}

	// Pass 1 — deny. Walk rules in policy file order; first matching object wins.
	// Deny rules short-circuit: the entire effect is denied as soon as one rule
	// matches any object.
	for _, r := range applicable {
		if r.verb != VerbDeny {
			continue
		}
		if !ruleMatchesEffectMeta(r, e) {
			continue
		}
		// Find the first matching object (deterministic: object list order).
		for _, o := range e.Objects {
			if !r.schemaMatches(o) {
				continue
			}
			if r.objectMatches(o) {
				return effectDecision{verb: verbDeny, rule: r, denyMatchingObject: o}
			}
		}
	}

	// Pass 2 — coverage. For each object, collect non-deny rules that cover it.
	// coverage[i] holds the covering rules for e.Objects[i].
	coverage := make(map[int][]*compiledStatementRule, len(e.Objects))
	for i, o := range e.Objects {
		for _, r := range applicable {
			if r.verb == VerbDeny {
				continue
			}
			if !ruleMatchesEffectMeta(r, e) {
				continue
			}
			if !r.schemaMatches(o) {
				continue
			}
			if !r.objectMatches(o) {
				continue
			}
			coverage[i] = append(coverage[i], r)
		}
	}

	// Implicit deny if any object has empty coverage.
	for i, o := range e.Objects {
		if len(coverage[i]) == 0 {
			return effectDecision{verb: verbImplicitDeny, uncoveredObject: o}
		}
	}

	// Pass 3 — most-restrictive verb across covering rules.
	// Walk coverage in object order, preserving rule order within each bucket
	// (rules stay in policy file order because `applicable` preserves that order).
	// This guarantees R14 order-independence of OUTCOMES: the result depends on
	// the rule set, not on evaluation path; only the RuleName tiebreak (D-OQ3)
	// uses file order.
	var (
		best        internalVerb = verbAllow
		primary     *compiledStatementRule
		approveRules []*compiledStatementRule
		auditRules   []*compiledStatementRule
		approveSeen  = map[string]bool{}
		auditSeen    = map[string]bool{}
	)
	for i := range e.Objects {
		for _, r := range coverage[i] {
			switch r.verb {
			case VerbApprove:
				if verbApprove > best {
					best = verbApprove
				}
				if !approveSeen[r.src.Name] {
					approveSeen[r.src.Name] = true
					approveRules = append(approveRules, r)
				}
			case VerbAudit:
				if verbAudit > best {
					best = verbAudit
				}
				if !auditSeen[r.src.Name] {
					auditSeen[r.src.Name] = true
					auditRules = append(auditRules, r)
				}
			// VerbAllow contributes coverage but no verb escalation. The primary
			// rule for an allow outcome is selected later (coverage[0][0]).
			}
		}
	}

	// Determine primary rule (D-OQ3: first by policy file order).
	switch best {
	case verbApprove:
		primary = approveRules[0]
	case verbAudit:
		primary = auditRules[0]
	default:
		// Allow: pick the first covering rule for the first object.
		primary = coverage[0][0]
	}

	return effectDecision{
		verb:                best,
		rule:                primary,
		contributingApprove: approveRules,
		contributingAudit:   auditRules,
	}
}

// isObjectlessGroup reports whether the group inherently has no objects
// in its classified effects (BEGIN/COMMIT/SAVEPOINT, SET/RESET, NOTIFY).
// Object-less effects in these groups must still be reachable through the
// policy — they would otherwise be unreachable under §10.2's per-object
// coverage rule.
func isObjectlessGroup(g effects.Group) bool {
	switch g {
	case effects.GroupTransaction, effects.GroupSession, effects.GroupNotify:
		return true
	}
	return false
}

// evaluateEffectObjectless handles effects with no Objects (e.g. transaction
// or session effects from BEGIN/COMMIT/SET). The §10.2 three-pass algorithm
// is per-object; for object-less effects we apply a degenerate version:
//
//   - A deny rule whose effect-meta matches and whose `objects:` filter is
//     empty (coversAllObjects) short-circuits to deny.
//   - Otherwise, the effect is covered by any non-deny rule whose effect-meta
//     matches and whose `objects:` filter is empty. The most-restrictive verb
//     across covering rules wins.
//   - If no rule covers the effect, fall back to implicit deny.
//
// A rule that constrains `objects:` (non-empty) cannot match an object-less
// effect — there is no object to match against.
func evaluateEffectObjectless(e effects.Effect, applicable []*compiledStatementRule) effectDecision {
	// Pass 1 — deny.
	for _, r := range applicable {
		if r.verb != VerbDeny {
			continue
		}
		if !ruleMatchesEffectMeta(r, e) {
			continue
		}
		if !r.coversAllObjects() {
			continue
		}
		return effectDecision{verb: verbDeny, rule: r}
	}

	// Pass 2 — coverage: any non-deny rule whose effect-meta matches and
	// whose objects filter is empty.
	var (
		coverage []*compiledStatementRule
	)
	for _, r := range applicable {
		if r.verb == VerbDeny {
			continue
		}
		if !ruleMatchesEffectMeta(r, e) {
			continue
		}
		if !r.coversAllObjects() {
			continue
		}
		coverage = append(coverage, r)
	}
	if len(coverage) == 0 {
		return effectDecision{verb: verbImplicitDeny}
	}

	// Pass 3 — most-restrictive verb across covering rules.
	var (
		best         internalVerb = verbAllow
		primary      *compiledStatementRule
		approveRules []*compiledStatementRule
		auditRules   []*compiledStatementRule
		approveSeen  = map[string]bool{}
		auditSeen    = map[string]bool{}
	)
	for _, r := range coverage {
		switch r.verb {
		case VerbApprove:
			if verbApprove > best {
				best = verbApprove
			}
			if !approveSeen[r.src.Name] {
				approveSeen[r.src.Name] = true
				approveRules = append(approveRules, r)
			}
		case VerbAudit:
			if verbAudit > best {
				best = verbAudit
			}
			if !auditSeen[r.src.Name] {
				auditSeen[r.src.Name] = true
				auditRules = append(auditRules, r)
			}
		}
	}
	switch best {
	case verbApprove:
		primary = approveRules[0]
	case verbAudit:
		primary = auditRules[0]
	default:
		primary = coverage[0]
	}
	return effectDecision{
		verb:                best,
		rule:                primary,
		contributingApprove: approveRules,
		contributingAudit:   auditRules,
	}
}

// ruleMatchesEffectMeta checks group/subtype/resolution for an effect.
// Per-object matching (schema + object globs) is done by the caller.
func ruleMatchesEffectMeta(r *compiledStatementRule, e effects.Effect) bool {
	if _, ok := r.groups[e.Group]; !ok {
		return false
	}
	if len(r.subtypes) > 0 {
		if _, ok := r.subtypes[e.Subtype]; !ok {
			return false
		}
	}
	if !r.matchesResolution(e.Resolution) {
		return false
	}
	return true
}

// foldEffects picks the most-restrictive per-effect verdict and turns it into
// a public Decision.
//
// Tiebreak semantics (locked during brainstorm):
//   - Lowest index wins among verbs at the same level (MatchingEffectIndex).
//   - Explicit deny beats implicit deny so RuleName is non-empty whenever
//     possible (verbDeny > verbImplicitDeny in compareInternalVerb).
func foldEffects(stmt effects.ClassifiedStatement, perEffect []effectDecision) Decision {
	bestIdx := 0
	for i := 1; i < len(perEffect); i++ {
		if compareInternalVerb(perEffect[i].verb, perEffect[bestIdx].verb) > 0 {
			bestIdx = i
		}
		// On exact tie: keep bestIdx (lower index wins).
	}
	d := perEffect[bestIdx]
	e := stmt.Effects[bestIdx]

	switch d.verb {
	case verbAllow:
		return Decision{
			Verb:                VerbAllow,
			RuleKind:            RuleKindStatement,
			RuleName:            d.rule.src.Name,
			MatchingEffectIndex: bestIdx,
			MatchingEffectGroup: e.Group,
			Reason:              d.rule.renderMessage(messageContextFor(e, stmt)),
		}

	case verbAudit:
		return Decision{
			Verb:                VerbAudit,
			RuleKind:            RuleKindStatement,
			RuleName:            d.rule.src.Name,
			MatchingEffectIndex: bestIdx,
			MatchingEffectGroup: e.Group,
			Reason:              d.rule.renderMessage(messageContextFor(e, stmt)),
		}

	case verbApprove:
		// Shortest timeout wins (D-OQ2 — most-restrictive principle applied to time).
		timeout := d.contributingApprove[0].timeout
		approveNames := make([]string, len(d.contributingApprove))
		for i, r := range d.contributingApprove {
			approveNames[i] = r.src.Name
			if r.timeout < timeout {
				timeout = r.timeout
			}
		}
		auditNames := make([]string, len(d.contributingAudit))
		for i, r := range d.contributingAudit {
			auditNames[i] = r.src.Name
		}
		return Decision{
			Verb:                   VerbApprove,
			RuleKind:               RuleKindStatement,
			RuleName:               d.rule.src.Name,
			MatchingEffectIndex:    bestIdx,
			MatchingEffectGroup:    e.Group,
			Reason:                 d.rule.renderMessage(messageContextFor(e, stmt)),
			ContributingAuditRules: auditNames,
			Approval: &ApprovalRequest{
				Timeout:                  timeout,
				ContributingApproveRules: approveNames,
			},
		}

	case verbImplicitDeny:
		return implicitDeny(stmt, bestIdx,
			fmt.Sprintf("no rule covers %q in %q effect", objectMatchField(d.uncoveredObject), e.Group))

	case verbDeny:
		return Decision{
			Verb:                VerbDeny,
			RuleKind:            RuleKindStatement,
			RuleName:            d.rule.src.Name,
			MatchingEffectIndex: bestIdx,
			MatchingEffectGroup: e.Group,
			Reason:              d.rule.renderMessage(messageContextFor(e, stmt)),
		}

	default:
		return implicitDeny(stmt, bestIdx, "unknown effect verdict")
	}
}

// compareInternalVerb returns +1, -1, or 0 like Compare-style helpers.
// Defined as a function (instead of inline `>`) so call sites read as
// "this is a tiebreak comparison" rather than "this is integer math".
//
// Order: allow < audit < approve < implicit_deny < deny. implicit_deny
// ranks just below explicit deny so the explicit deny path wins ties
// (preserving Decision.RuleName).
func compareInternalVerb(a, b internalVerb) int {
	if a > b {
		return 1
	}
	if a < b {
		return -1
	}
	return 0
}

// messageContextFor builds the template-render context for an effect.
func messageContextFor(e effects.Effect, stmt effects.ClassifiedStatement) messageContext {
	var schema, object string
	if len(e.Objects) > 0 {
		schema = e.Objects[0].Schema
		object = objectMatchField(e.Objects[0])
	}
	subtype := ""
	if e.Subtype != effects.SubtypeNone {
		subtype = e.Subtype.String()
	}
	return messageContext{
		Operation: e.Group.String(),
		Subtype:   subtype,
		Schema:    schema,
		Object:    object,
		Verb:      stmt.RawVerb,
	}
}

// implicitDeny builds a Decision representing a deny with no matching rule
// (implicit deny). RuleName is "" per the §7 convention; callers can
// distinguish implicit from explicit deny by testing RuleName == "".
func implicitDeny(stmt effects.ClassifiedStatement, idx int, reason string) Decision {
	d := Decision{
		Verb:                VerbDeny,
		RuleKind:            RuleKindStatement,
		MatchingEffectIndex: idx,
		Reason:              reason,
	}
	if idx >= 0 && idx < len(stmt.Effects) {
		d.MatchingEffectGroup = stmt.Effects[idx].Group
	}
	return d
}
