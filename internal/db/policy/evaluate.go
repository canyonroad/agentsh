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
// Ordering:
// verbAllow < verbAudit < verbRedirect < verbApprove < verbImplicitDeny < verbDeny.
// Higher value = more restrictive. verbImplicitDeny ranks just below verbDeny
// so explicit deny wins ties, giving a non-empty RuleName whenever possible.
type internalVerb uint8

const (
	verbAllow        internalVerb = iota
	verbAudit                     // more restrictive than allow
	verbRedirect                  // more restrictive than audit
	verbApprove                   // more restrictive than redirect
	verbImplicitDeny              // more restrictive than approve; loses to explicit deny on tie
	verbDeny                      // most restrictive
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
	// coverage rules. Treat those as covered by any rule with no object selector
	// family whose effect-meta matches. Resolved-only procedural function effects
	// use canonical selector coverage below.
	if len(e.Objects) == 0 {
		if isResolvedOnlyFunctionEffect(e) {
			return evaluateEffectResolvedOnly(e, applicable)
		}
		if isObjectlessEffect(e) {
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
		for i, o := range e.Objects {
			if ok, _ := ruleMatchesObjectSlot(r, e, i); ok {
				return effectDecision{verb: verbDeny, rule: r, denyMatchingObject: o}
			}
		}
	}

	// Pass 2 — coverage. For each object, collect non-deny rules that cover it.
	// coverage[i] holds the covering rules for e.Objects[i].
	coverage := make(map[int][]*compiledStatementRule, len(e.Objects))
	for i := range e.Objects {
		for _, r := range applicable {
			if r.verb == VerbDeny {
				continue
			}
			if !ruleMatchesEffectMeta(r, e) {
				continue
			}
			if ok, _ := ruleMatchesObjectSlot(r, e, i); ok {
				coverage[i] = append(coverage[i], r)
			}
		}
	}

	// Implicit deny if any object has empty coverage.
	for i, o := range e.Objects {
		if len(coverage[i]) == 0 {
			return effectDecision{verb: verbImplicitDeny, uncoveredObject: o}
		}
	}

	// Pass 3 — most-restrictive verb across covering rules. Fold in policy file
	// order so same-verb primary RuleName ties are independent of object order.
	return foldCoverageRules(coverageRulesInPolicyOrder(applicable, coverage, len(e.Objects)))
}

func resolvedObjectForSlot(e effects.Effect, idx int) (effects.ResolvedObjectRef, bool) {
	if idx < 0 || idx >= len(e.Objects) {
		return effects.ResolvedObjectRef{}, false
	}
	o := e.Objects[idx]
	switch {
	case isRelationObjectKind(o.Kind):
		ordinal := relationObjectSlotOrdinal(e.Objects, idx)
		resolved, ok := resolvedRelationObjectAtOrdinal(e.ResolvedObjects, ordinal)
		if !ok || !resolvedObjectCompatibleWithSlot(o, resolved) {
			return effects.ResolvedObjectRef{}, false
		}
		return resolved, true
	case o.Kind == effects.ObjectFunction:
		ordinal := functionObjectSlotOrdinal(e.Objects, idx)
		resolved, ok := resolvedFunctionObjectAtOrdinal(e.ResolvedObjects, ordinal)
		if !ok || !resolvedObjectCompatibleWithSlot(o, resolved) {
			return effects.ResolvedObjectRef{}, false
		}
		return resolved, true
	}
	for _, resolved := range e.ResolvedObjects {
		if resolvedObjectCompatibleWithSlot(o, resolved) {
			return resolved, true
		}
	}
	return effects.ResolvedObjectRef{}, false
}

func relationObjectSlotOrdinal(objects []effects.ObjectRef, idx int) int {
	ordinal := 0
	for i := 0; i <= idx && i < len(objects); i++ {
		if !isRelationObjectKind(objects[i].Kind) {
			continue
		}
		if i == idx {
			return ordinal
		}
		ordinal++
	}
	return -1
}

func functionObjectSlotOrdinal(objects []effects.ObjectRef, idx int) int {
	ordinal := 0
	for i := 0; i <= idx && i < len(objects); i++ {
		if objects[i].Kind != effects.ObjectFunction {
			continue
		}
		if i == idx {
			return ordinal
		}
		ordinal++
	}
	return -1
}

func resolvedRelationObjectAtOrdinal(resolvedObjects []effects.ResolvedObjectRef, ordinal int) (effects.ResolvedObjectRef, bool) {
	if ordinal < 0 {
		return effects.ResolvedObjectRef{}, false
	}
	count := 0
	for _, resolved := range resolvedObjects {
		if resolved.Kind != effects.ResolvedObjectRelation {
			continue
		}
		if count == ordinal {
			return resolved, true
		}
		count++
	}
	return effects.ResolvedObjectRef{}, false
}

func resolvedFunctionObjectAtOrdinal(resolvedObjects []effects.ResolvedObjectRef, ordinal int) (effects.ResolvedObjectRef, bool) {
	if ordinal < 0 {
		return effects.ResolvedObjectRef{}, false
	}
	count := 0
	for _, resolved := range resolvedObjects {
		if resolved.Kind != effects.ResolvedObjectFunction {
			continue
		}
		if count == ordinal {
			return resolved, true
		}
		count++
	}
	return effects.ResolvedObjectRef{}, false
}

func resolvedObjectCompatibleWithSlot(o effects.ObjectRef, resolved effects.ResolvedObjectRef) bool {
	if o.Name == "" || resolved.Name == "" || o.Name != resolved.Name {
		return false
	}
	if o.Schema != "" && o.Schema != resolved.Schema {
		return false
	}
	switch resolved.Kind {
	case effects.ResolvedObjectRelation:
		return isRelationObjectKind(o.Kind)
	case effects.ResolvedObjectFunction:
		return o.Kind == effects.ObjectFunction
	default:
		return false
	}
}

func isRelationObjectKind(kind effects.ObjectKind) bool {
	switch kind {
	case effects.ObjectTable, effects.ObjectView, effects.ObjectSequence:
		return true
	default:
		return false
	}
}

func ruleMatchesObjectSlot(r *compiledStatementRule, e effects.Effect, idx int) (bool, string) {
	if idx < 0 || idx >= len(e.Objects) {
		return false, ""
	}
	o := e.Objects[idx]
	resolved, hasResolved := resolvedObjectForSlot(e, idx)
	if !r.schemaMatchesObjectSlot(o, resolved, hasResolved) {
		return false, ""
	}
	if !r.hasObjectSelectors() {
		return true, "all"
	}
	if len(r.objects) > 0 && r.objectMatches(o) {
		return true, "objects"
	}
	if hasResolved && r.relationMatches(resolved) {
		return true, "relations"
	}
	if hasResolved && r.functionMatches(resolved) {
		return true, "functions"
	}
	return false, ""
}

func coverageRulesInPolicyOrder(applicable []*compiledStatementRule, coverage map[int][]*compiledStatementRule, objectCount int) []*compiledStatementRule {
	covered := map[*compiledStatementRule]bool{}
	for i := 0; i < objectCount; i++ {
		for _, r := range coverage[i] {
			covered[r] = true
		}
	}

	out := make([]*compiledStatementRule, 0, len(covered))
	for _, r := range applicable {
		if covered[r] {
			out = append(out, r)
		}
	}
	return out
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

// isObjectlessEffect reports whether the effect is inherently object-less and
// should be evaluated using the degenerate per-group path rather than returning
// verbImplicitDeny. This extends isObjectlessGroup for cases where the group
// alone is insufficient: unresolved FunctionCall protocol effects (Subtype ==
// SubtypeFunctionCallProtocol) carry only a function OID with no object name,
// so they must be reachable through object-less coverage rules.
// SQL-escalated unknown-function procedural effects (Group == GroupProcedural,
// Subtype == 0) remain implicit-deny by design (fail-closed escalation).
func isObjectlessEffect(e effects.Effect) bool {
	if isObjectlessGroup(e.Group) {
		return true
	}
	// FunctionCall protocol: OID-only effect, no resolvable Objects.
	return e.Subtype == effects.SubtypeFunctionCallProtocol && len(e.ResolvedObjects) == 0
}

func isResolvedOnlyFunctionEffect(e effects.Effect) bool {
	if len(e.Objects) != 0 || e.Group != effects.GroupProcedural {
		return false
	}
	for _, resolved := range e.ResolvedObjects {
		if resolved.Kind == effects.ResolvedObjectFunction {
			return true
		}
	}
	return false
}

func evaluateEffectResolvedOnly(e effects.Effect, applicable []*compiledStatementRule) effectDecision {
	for _, r := range applicable {
		if r.verb != VerbDeny || !ruleMatchesEffectMeta(r, e) {
			continue
		}
		for _, resolved := range e.ResolvedObjects {
			if !resolvedOnlyFunctionRuleMatches(r, resolved) {
				continue
			}
			if !r.hasObjectSelectors() || r.functionMatches(resolved) {
				return effectDecision{verb: verbDeny, rule: r}
			}
		}
	}

	var coverage []*compiledStatementRule
	for _, r := range applicable {
		if r.verb == VerbDeny || !ruleMatchesEffectMeta(r, e) {
			continue
		}
		for _, resolved := range e.ResolvedObjects {
			if !resolvedOnlyFunctionRuleMatches(r, resolved) {
				continue
			}
			if !r.hasObjectSelectors() || r.functionMatches(resolved) {
				coverage = append(coverage, r)
				break
			}
		}
	}
	if len(coverage) == 0 {
		return effectDecision{verb: verbImplicitDeny}
	}
	return foldCoverageRules(coverage)
}

func resolvedOnlyFunctionRuleMatches(r *compiledStatementRule, resolved effects.ResolvedObjectRef) bool {
	return resolved.Kind == effects.ResolvedObjectFunction && r.schemaMatchesResolvedObject(resolved)
}

// evaluateEffectObjectless handles effects with no Objects (e.g. transaction
// or session effects from BEGIN/COMMIT/SET). The §10.2 three-pass algorithm
// is per-object; for object-less effects we apply a degenerate version:
//
//   - A deny rule whose effect-meta matches and has no object selector family
//     short-circuits to deny.
//   - Otherwise, the effect is covered by any non-deny rule whose effect-meta
//     matches and has no object selector family. The most-restrictive verb
//     across covering rules wins.
//   - If no rule covers the effect, fall back to implicit deny.
//
// A rule that constrains any object selector family cannot match an object-less
// effect.
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

	// Pass 2 — coverage: any non-deny rule whose effect-meta matches and has no
	// object selector family.
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
	return foldCoverageRules(coverage)
}

func foldCoverageRules(coverage []*compiledStatementRule) effectDecision {
	var (
		best         internalVerb = verbAllow
		primary      *compiledStatementRule
		approveRules []*compiledStatementRule
		auditRules   []*compiledStatementRule
		redirectRule *compiledStatementRule
		approveSeen  = map[string]bool{}
		auditSeen    = map[string]bool{}
	)
	for _, r := range coverage {
		switch r.verb {
		case VerbRedirect:
			if verbRedirect > best {
				best = verbRedirect
			}
			if redirectRule == nil {
				redirectRule = r
			}
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
	case verbRedirect:
		primary = redirectRule
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
// Per-object selector matching is done by the caller.
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

	case verbRedirect:
		return Decision{
			Verb:                VerbRedirect,
			RuleKind:            RuleKindStatement,
			RuleName:            d.rule.src.Name,
			MatchingEffectIndex: bestIdx,
			MatchingEffectGroup: e.Group,
			Reason:              d.rule.renderMessage(messageContextFor(e, stmt)),
			Redirect:            copyRedirectDecision(d.rule.redirect),
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
// Order: allow < audit < redirect < approve < implicit_deny < deny.
// implicit_deny ranks just below explicit deny so the explicit deny path wins
// ties (preserving Decision.RuleName).
func compareInternalVerb(a, b internalVerb) int {
	if a > b {
		return 1
	}
	if a < b {
		return -1
	}
	return 0
}

func copyRedirectDecision(r *RedirectDecision) *RedirectDecision {
	if r == nil {
		return nil
	}
	return &RedirectDecision{
		SourceRelation: r.SourceRelation,
		TargetRelation: r.TargetRelation,
	}
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
