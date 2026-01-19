package ancestry

import (
	"sort"
	"strings"

	"github.com/agentsh/agentsh/internal/policy/pattern"
)

// ChainCondition represents conditions for evaluating process chains.
// Conditions can be composed with And/Or for complex matching.
type ChainCondition struct {
	// Via chain conditions
	ViaIndex       *int     `yaml:"via_index,omitempty"`        // Check specific via position (0-indexed)
	ViaIndexValue  string   `yaml:"via_index_value,omitempty"`  // Value to match at ViaIndex
	ViaContains    []string `yaml:"via_contains,omitempty"`     // Any of these patterns in via
	ViaNotContains []string `yaml:"via_not_contains,omitempty"` // None of these patterns in via
	ViaMatches     []string `yaml:"via_matches,omitempty"`      // Pattern match against via entries

	// Class-based conditions
	ClassContains    []string `yaml:"class_contains,omitempty"`     // Any of these classes in chain
	ClassNotContains []string `yaml:"class_not_contains,omitempty"` // None of these classes in chain

	// Consecutive pattern detection (shell laundering)
	ConsecutiveClass *ConsecutiveMatch `yaml:"consecutive_class,omitempty"` // Consecutive class occurrences
	ConsecutiveComm  *ConsecutiveMatch `yaml:"consecutive_comm,omitempty"`  // Consecutive comm occurrences

	// Depth conditions
	DepthEQ *int `yaml:"depth_eq,omitempty"` // Depth equals
	DepthGT *int `yaml:"depth_gt,omitempty"` // Depth greater than
	DepthLT *int `yaml:"depth_lt,omitempty"` // Depth less than
	DepthGE *int `yaml:"depth_ge,omitempty"` // Depth greater or equal
	DepthLE *int `yaml:"depth_le,omitempty"` // Depth less or equal

	// Taint flags
	IsTainted *bool `yaml:"is_tainted,omitempty"` // Is descended from AI tool
	IsAgent   *bool `yaml:"is_agent,omitempty"`   // Is detected as agent

	// Execution context conditions
	EnvContains  []string `yaml:"env_contains,omitempty"`  // Environment variable patterns
	ArgsContain  []string `yaml:"args_contain,omitempty"`  // Command argument patterns
	CommMatches  []string `yaml:"comm_matches,omitempty"`  // Command name patterns
	PathMatches  []string `yaml:"path_matches,omitempty"`  // Executable path patterns

	// Source conditions
	SourceName    []string `yaml:"source_name,omitempty"`    // Source process name patterns
	SourceContext []string `yaml:"source_context,omitempty"` // Source context name patterns

	// Logical composition
	Or  []*ChainCondition `yaml:"or,omitempty"`  // OR sub-conditions (any must match)
	And []*ChainCondition `yaml:"and,omitempty"` // AND sub-conditions (all must match)
	Not *ChainCondition   `yaml:"not,omitempty"` // NOT sub-condition (must not match)
}

// ConsecutiveMatch specifies a consecutive occurrence requirement.
type ConsecutiveMatch struct {
	Value   string `yaml:"value"`    // Class name or comm pattern
	CountGE int    `yaml:"count_ge"` // Count must be >= this
	CountLE int    `yaml:"count_le"` // Count must be <= this (0 = no limit)
}

// ExecutionContext provides information about the current execution.
type ExecutionContext struct {
	Comm    string            // Current command name
	Args    []string          // Command arguments
	ExePath string            // Executable path
	Env     map[string]string // Environment variables
}

// ConditionEvaluator evaluates chain conditions.
type ConditionEvaluator struct {
	registry   *pattern.ClassRegistry
	classifier *Classifier
}

// NewConditionEvaluator creates a new condition evaluator.
func NewConditionEvaluator() *ConditionEvaluator {
	return &ConditionEvaluator{
		registry:   pattern.NewClassRegistry(),
		classifier: NewClassifier(),
	}
}

// NewConditionEvaluatorWithRegistry creates an evaluator with custom registry.
func NewConditionEvaluatorWithRegistry(registry *pattern.ClassRegistry) *ConditionEvaluator {
	return &ConditionEvaluator{
		registry:   registry,
		classifier: NewClassifierWithRegistry(registry),
	}
}

// Evaluate checks if a taint and execution context match a condition.
func (e *ConditionEvaluator) Evaluate(cond *ChainCondition, taint *ProcessTaint, ctx *ExecutionContext) bool {
	if cond == nil {
		return true // No condition = always matches
	}

	// Handle logical composition first
	if len(cond.Or) > 0 {
		for _, sub := range cond.Or {
			if e.Evaluate(sub, taint, ctx) {
				return true
			}
		}
		return false
	}

	if len(cond.And) > 0 {
		for _, sub := range cond.And {
			if !e.Evaluate(sub, taint, ctx) {
				return false
			}
		}
		return true
	}

	if cond.Not != nil {
		return !e.Evaluate(cond.Not, taint, ctx)
	}

	// All leaf conditions must pass
	return e.evaluateLeafConditions(cond, taint, ctx)
}

// evaluateLeafConditions checks all non-composite conditions.
func (e *ConditionEvaluator) evaluateLeafConditions(cond *ChainCondition, taint *ProcessTaint, ctx *ExecutionContext) bool {
	// Via index check
	if cond.ViaIndex != nil && cond.ViaIndexValue != "" {
		if !e.checkViaIndex(taint, *cond.ViaIndex, cond.ViaIndexValue) {
			return false
		}
	}

	// Via contains
	if len(cond.ViaContains) > 0 {
		if !e.checkViaContains(taint, cond.ViaContains) {
			return false
		}
	}

	// Via not contains
	if len(cond.ViaNotContains) > 0 {
		if e.checkViaContains(taint, cond.ViaNotContains) {
			return false // Fail if any match
		}
	}

	// Via matches (pattern)
	if len(cond.ViaMatches) > 0 {
		if !e.checkViaMatches(taint, cond.ViaMatches) {
			return false
		}
	}

	// Class contains
	if len(cond.ClassContains) > 0 {
		if !e.checkClassContains(taint, cond.ClassContains) {
			return false
		}
	}

	// Class not contains
	if len(cond.ClassNotContains) > 0 {
		if e.checkClassContains(taint, cond.ClassNotContains) {
			return false
		}
	}

	// Consecutive class
	if cond.ConsecutiveClass != nil {
		if !e.checkConsecutiveClass(taint, cond.ConsecutiveClass) {
			return false
		}
	}

	// Consecutive comm
	if cond.ConsecutiveComm != nil {
		if !e.checkConsecutiveComm(taint, cond.ConsecutiveComm) {
			return false
		}
	}

	// Depth conditions
	if !e.checkDepth(taint, cond) {
		return false
	}

	// Taint flags
	if cond.IsTainted != nil {
		isTainted := taint != nil
		if *cond.IsTainted != isTainted {
			return false
		}
	}

	if cond.IsAgent != nil {
		isAgent := taint != nil && taint.IsAgent
		if *cond.IsAgent != isAgent {
			return false
		}
	}

	// Execution context conditions
	if ctx != nil {
		if len(cond.EnvContains) > 0 {
			if !e.checkEnvContains(ctx, cond.EnvContains) {
				return false
			}
		}

		if len(cond.ArgsContain) > 0 {
			if !e.checkArgsContain(ctx, cond.ArgsContain) {
				return false
			}
		}

		if len(cond.CommMatches) > 0 {
			if !e.checkPatternMatches(ctx.Comm, cond.CommMatches) {
				return false
			}
		}

		if len(cond.PathMatches) > 0 {
			if !e.checkPatternMatches(ctx.ExePath, cond.PathMatches) {
				return false
			}
		}
	}

	// Source conditions
	if len(cond.SourceName) > 0 {
		if !e.checkSourceName(taint, cond.SourceName) {
			return false
		}
	}

	if len(cond.SourceContext) > 0 {
		if !e.checkSourceContext(taint, cond.SourceContext) {
			return false
		}
	}

	return true
}

func (e *ConditionEvaluator) checkViaIndex(taint *ProcessTaint, index int, value string) bool {
	if taint == nil || index < 0 || index >= len(taint.Via) {
		return false
	}

	p, err := pattern.Compile(value)
	if err != nil {
		return taint.Via[index] == value
	}

	match, _ := p.MatchWithResolver(taint.Via[index], e.registry.GetResolver())
	return match
}

func (e *ConditionEvaluator) checkViaContains(taint *ProcessTaint, patterns []string) bool {
	if taint == nil {
		return false
	}

	for _, p := range patterns {
		compiled, err := pattern.Compile(p)
		if err != nil {
			// Exact match fallback
			for _, v := range taint.Via {
				if v == p {
					return true
				}
			}
			continue
		}

		for _, v := range taint.Via {
			match, _ := compiled.MatchWithResolver(v, e.registry.GetResolver())
			if match {
				return true
			}
		}
	}

	return false
}

func (e *ConditionEvaluator) checkViaMatches(taint *ProcessTaint, patterns []string) bool {
	if taint == nil {
		return false
	}

	for _, p := range patterns {
		compiled, err := pattern.Compile(p)
		if err != nil {
			continue
		}

		for _, v := range taint.Via {
			match, _ := compiled.MatchWithResolver(v, e.registry.GetResolver())
			if match {
				return true
			}
		}
	}

	return false
}

func (e *ConditionEvaluator) checkClassContains(taint *ProcessTaint, classNames []string) bool {
	if taint == nil {
		return false
	}

	for _, className := range classNames {
		targetClass := ParseProcessClass(className)
		if targetClass == ClassUnknown && className != "unknown" {
			continue
		}

		for _, c := range taint.ViaClasses {
			if c == targetClass {
				return true
			}
		}
	}

	return false
}

func (e *ConditionEvaluator) checkConsecutiveClass(taint *ProcessTaint, match *ConsecutiveMatch) bool {
	if taint == nil || match == nil {
		return false
	}

	targetClass := ParseProcessClass(match.Value)
	count := CountConsecutive(taint.ViaClasses, targetClass)

	if match.CountGE > 0 && count < match.CountGE {
		return false
	}
	if match.CountLE > 0 && count > match.CountLE {
		return false
	}

	return true
}

func (e *ConditionEvaluator) checkConsecutiveComm(taint *ProcessTaint, match *ConsecutiveMatch) bool {
	if taint == nil || match == nil {
		return false
	}

	count := CountConsecutiveComm(taint.Via, []string{match.Value})

	if match.CountGE > 0 && count < match.CountGE {
		return false
	}
	if match.CountLE > 0 && count > match.CountLE {
		return false
	}

	return true
}

func (e *ConditionEvaluator) checkDepth(taint *ProcessTaint, cond *ChainCondition) bool {
	depth := 0
	if taint != nil {
		depth = taint.Depth
	}

	if cond.DepthEQ != nil && depth != *cond.DepthEQ {
		return false
	}
	if cond.DepthGT != nil && depth <= *cond.DepthGT {
		return false
	}
	if cond.DepthLT != nil && depth >= *cond.DepthLT {
		return false
	}
	if cond.DepthGE != nil && depth < *cond.DepthGE {
		return false
	}
	if cond.DepthLE != nil && depth > *cond.DepthLE {
		return false
	}

	return true
}

func (e *ConditionEvaluator) checkEnvContains(ctx *ExecutionContext, patterns []string) bool {
	if ctx == nil || ctx.Env == nil {
		return false
	}

	for _, p := range patterns {
		// Check if pattern matches any env key or value
		compiled, err := pattern.Compile(p)
		if err != nil {
			// Exact match
			for k, v := range ctx.Env {
				if k == p || v == p || strings.Contains(k+"="+v, p) {
					return true
				}
			}
			continue
		}

		for k, v := range ctx.Env {
			match, _ := compiled.MatchWithResolver(k, e.registry.GetResolver())
			if match {
				return true
			}
			match, _ = compiled.MatchWithResolver(v, e.registry.GetResolver())
			if match {
				return true
			}
		}
	}

	return false
}

func (e *ConditionEvaluator) checkArgsContain(ctx *ExecutionContext, patterns []string) bool {
	if ctx == nil {
		return false
	}

	for _, p := range patterns {
		compiled, err := pattern.Compile(p)
		if err != nil {
			// Exact match
			for _, arg := range ctx.Args {
				if arg == p || strings.Contains(arg, p) {
					return true
				}
			}
			continue
		}

		for _, arg := range ctx.Args {
			match, _ := compiled.MatchWithResolver(arg, e.registry.GetResolver())
			if match {
				return true
			}
		}
	}

	return false
}

func (e *ConditionEvaluator) checkPatternMatches(value string, patterns []string) bool {
	if value == "" {
		return false
	}

	for _, p := range patterns {
		compiled, err := pattern.Compile(p)
		if err != nil {
			if value == p {
				return true
			}
			continue
		}

		match, _ := compiled.MatchWithResolver(value, e.registry.GetResolver())
		if match {
			return true
		}
	}

	return false
}

func (e *ConditionEvaluator) checkSourceName(taint *ProcessTaint, patterns []string) bool {
	if taint == nil {
		return false
	}
	return e.checkPatternMatches(taint.SourceName, patterns)
}

func (e *ConditionEvaluator) checkSourceContext(taint *ProcessTaint, patterns []string) bool {
	if taint == nil {
		return false
	}
	return e.checkPatternMatches(taint.ContextName, patterns)
}

// ChainAction specifies the action to take when a chain rule matches.
type ChainAction string

const (
	// ActionAllowNormalPolicy applies normal (non-context) policy rules.
	ActionAllowNormalPolicy ChainAction = "allow_normal_policy"

	// ActionApplyContextPolicy applies the process context policy rules.
	ActionApplyContextPolicy ChainAction = "apply_context_policy"

	// ActionDeny denies the operation.
	ActionDeny ChainAction = "deny"

	// ActionApprove requires explicit approval.
	ActionApprove ChainAction = "approve"

	// ActionMarkAsAgent marks the process as an AI agent.
	ActionMarkAsAgent ChainAction = "mark_as_agent"

	// ActionAllow allows the operation unconditionally.
	ActionAllow ChainAction = "allow"
)

// ChainRule defines a rule for evaluating process chains.
type ChainRule struct {
	Name        string          `yaml:"name"`
	Description string          `yaml:"description,omitempty"`
	Priority    int             `yaml:"priority"`    // Higher = evaluated first
	Condition   *ChainCondition `yaml:"condition"`   // When this rule applies
	Action      ChainAction     `yaml:"action"`      // What to do
	Message     string          `yaml:"message,omitempty"`
	Continue    bool            `yaml:"continue"`    // Keep evaluating after this rule
}

// ChainRuleEvaluator evaluates chain rules.
type ChainRuleEvaluator struct {
	evaluator *ConditionEvaluator
	rules     []ChainRule
}

// NewChainRuleEvaluator creates a new rule evaluator.
func NewChainRuleEvaluator() *ChainRuleEvaluator {
	return &ChainRuleEvaluator{
		evaluator: NewConditionEvaluator(),
	}
}

// SetRules sets the rules to evaluate (will be sorted by priority).
func (e *ChainRuleEvaluator) SetRules(rules []ChainRule) {
	e.rules = make([]ChainRule, len(rules))
	copy(e.rules, rules)

	// Sort by priority (descending - higher first)
	sort.Slice(e.rules, func(i, j int) bool {
		return e.rules[i].Priority > e.rules[j].Priority
	})
}

// AddRule adds a rule (maintains priority order).
func (e *ChainRuleEvaluator) AddRule(rule ChainRule) {
	e.rules = append(e.rules, rule)
	sort.Slice(e.rules, func(i, j int) bool {
		return e.rules[i].Priority > e.rules[j].Priority
	})
}

// Evaluate evaluates rules against a taint and context.
// Returns the first matching rule's action, or nil if no rules match.
func (e *ChainRuleEvaluator) Evaluate(taint *ProcessTaint, ctx *ExecutionContext) *ChainRule {
	for i := range e.rules {
		rule := &e.rules[i]
		if e.evaluator.Evaluate(rule.Condition, taint, ctx) {
			return rule
		}
	}
	return nil
}

// EvaluateAll evaluates all rules and returns all matching rules.
// Useful for debugging or when Continue=true rules need to be collected.
func (e *ChainRuleEvaluator) EvaluateAll(taint *ProcessTaint, ctx *ExecutionContext) []*ChainRule {
	var matches []*ChainRule

	for i := range e.rules {
		rule := &e.rules[i]
		if e.evaluator.Evaluate(rule.Condition, taint, ctx) {
			matches = append(matches, rule)
			if !rule.Continue {
				break
			}
		}
	}

	return matches
}

// EvaluateWithContinue evaluates rules, collecting all matching rules
// until a non-Continue rule matches.
func (e *ChainRuleEvaluator) EvaluateWithContinue(taint *ProcessTaint, ctx *ExecutionContext) ([]*ChainRule, ChainAction) {
	var matches []*ChainRule
	var finalAction ChainAction

	for i := range e.rules {
		rule := &e.rules[i]
		if e.evaluator.Evaluate(rule.Condition, taint, ctx) {
			matches = append(matches, rule)
			finalAction = rule.Action

			if !rule.Continue {
				break
			}
		}
	}

	return matches, finalAction
}
