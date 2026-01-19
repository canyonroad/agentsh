package policy

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/agentsh/agentsh/internal/policy/ancestry"
	"github.com/agentsh/agentsh/internal/policy/identity"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/gobwas/glob"
)

// ContextEngine extends Engine with taint-aware policy evaluation.
type ContextEngine struct {
	*Engine
	taintCache *ancestry.TaintCache
	matcher    *identity.ProcessMatcher
	contexts   map[string]*compiledContext
}

// compiledContext holds pre-compiled patterns for a ProcessContext.
type compiledContext struct {
	config          *ProcessContext
	chainEvaluator  *ancestry.ChainRuleEvaluator
	allowedCmds     []glob.Glob
	deniedCmds      []glob.Glob
	requireApproval []glob.Glob
	overrides       map[string]*compiledOverride
}

type compiledOverride struct {
	argsAllow []glob.Glob
	argsDeny  []glob.Glob
	defDecision string
}

// ContextEngineConfig configures the context engine.
type ContextEngineConfig struct {
	TaintCache *ancestry.TaintCache
	Matcher    *identity.ProcessMatcher
}

// NewContextEngine creates a context-aware policy engine.
func NewContextEngine(p *Policy, enforceApprovals bool, cfg ContextEngineConfig) (*ContextEngine, error) {
	base, err := NewEngine(p, enforceApprovals)
	if err != nil {
		return nil, err
	}

	ce := &ContextEngine{
		Engine:     base,
		taintCache: cfg.TaintCache,
		matcher:    cfg.Matcher,
		contexts:   make(map[string]*compiledContext),
	}

	// Compile process contexts
	for name, ctx := range p.ProcessContexts {
		compiled, err := compileContext(&ctx)
		if err != nil {
			return nil, fmt.Errorf("compile context %q: %w", name, err)
		}
		ce.contexts[name] = compiled
	}

	return ce, nil
}

// compileContext compiles a ProcessContext for efficient evaluation.
func compileContext(ctx *ProcessContext) (*compiledContext, error) {
	cc := &compiledContext{
		config:    ctx,
		overrides: make(map[string]*compiledOverride),
	}

	// Compile chain rules
	if len(ctx.ChainRules) > 0 {
		cc.chainEvaluator = ancestry.NewChainRuleEvaluator()
		rules := make([]ancestry.ChainRule, 0, len(ctx.ChainRules))
		for _, rc := range ctx.ChainRules {
			rule := ancestry.ChainRule{
				Name:     rc.Name,
				Priority: rc.Priority,
				Action:   ancestry.ChainAction(rc.Action),
				Message:  rc.Message,
				Continue: rc.Continue,
			}
			if rc.Condition != nil {
				rule.Condition = convertConditionConfig(rc.Condition)
			}
			rules = append(rules, rule)
		}
		cc.chainEvaluator.SetRules(rules)
	}

	// Compile allowed commands
	for _, cmd := range ctx.AllowedCommands {
		g, err := glob.Compile(cmd)
		if err != nil {
			return nil, fmt.Errorf("compile allowed command %q: %w", cmd, err)
		}
		cc.allowedCmds = append(cc.allowedCmds, g)
	}

	// Compile denied commands
	for _, cmd := range ctx.DeniedCommands {
		g, err := glob.Compile(cmd)
		if err != nil {
			return nil, fmt.Errorf("compile denied command %q: %w", cmd, err)
		}
		cc.deniedCmds = append(cc.deniedCmds, g)
	}

	// Compile require approval commands
	for _, cmd := range ctx.RequireApproval {
		g, err := glob.Compile(cmd)
		if err != nil {
			return nil, fmt.Errorf("compile require_approval command %q: %w", cmd, err)
		}
		cc.requireApproval = append(cc.requireApproval, g)
	}

	// Compile command overrides
	for cmd, override := range ctx.CommandOverrides {
		co := &compiledOverride{defDecision: override.Default}
		for _, pat := range override.ArgsAllow {
			g, err := glob.Compile(pat)
			if err != nil {
				return nil, fmt.Errorf("compile override %q args_allow %q: %w", cmd, pat, err)
			}
			co.argsAllow = append(co.argsAllow, g)
		}
		for _, pat := range override.ArgsDeny {
			g, err := glob.Compile(pat)
			if err != nil {
				return nil, fmt.Errorf("compile override %q args_deny %q: %w", cmd, pat, err)
			}
			co.argsDeny = append(co.argsDeny, g)
		}
		cc.overrides[strings.ToLower(cmd)] = co
	}

	return cc, nil
}

// convertConditionConfig converts YAML config to ancestry.ChainCondition.
func convertConditionConfig(cfg *ChainConditionConfig) *ancestry.ChainCondition {
	if cfg == nil {
		return nil
	}

	cond := &ancestry.ChainCondition{
		ViaIndex:         cfg.ViaIndex,
		ViaIndexValue:    cfg.ViaIndexValue,
		ViaContains:      cfg.ViaContains,
		ViaNotContains:   cfg.ViaNotContains,
		ViaMatches:       cfg.ViaMatches,
		ClassContains:    cfg.ClassContains,
		ClassNotContains: cfg.ClassNotContains,
		DepthEQ:          cfg.DepthEQ,
		DepthGT:          cfg.DepthGT,
		DepthLT:          cfg.DepthLT,
		DepthGE:          cfg.DepthGE,
		DepthLE:          cfg.DepthLE,
		IsTainted:        cfg.IsTainted,
		IsAgent:          cfg.IsAgent,
		EnvContains:      cfg.EnvContains,
		ArgsContain:      cfg.ArgsContain,
		CommMatches:      cfg.CommMatches,
		PathMatches:      cfg.PathMatches,
		SourceName:       cfg.SourceName,
		SourceContext:    cfg.SourceContext,
	}

	if cfg.ConsecutiveClass != nil {
		cond.ConsecutiveClass = &ancestry.ConsecutiveMatch{
			Value:   cfg.ConsecutiveClass.Value,
			CountGE: cfg.ConsecutiveClass.CountGE,
			CountLE: cfg.ConsecutiveClass.CountLE,
		}
	}
	if cfg.ConsecutiveComm != nil {
		cond.ConsecutiveComm = &ancestry.ConsecutiveMatch{
			Value:   cfg.ConsecutiveComm.Value,
			CountGE: cfg.ConsecutiveComm.CountGE,
			CountLE: cfg.ConsecutiveComm.CountLE,
		}
	}

	// Recursive conversion for logical operators
	if len(cfg.Or) > 0 {
		cond.Or = make([]*ancestry.ChainCondition, len(cfg.Or))
		for i, sub := range cfg.Or {
			cond.Or[i] = convertConditionConfig(sub)
		}
	}
	if len(cfg.And) > 0 {
		cond.And = make([]*ancestry.ChainCondition, len(cfg.And))
		for i, sub := range cfg.And {
			cond.And[i] = convertConditionConfig(sub)
		}
	}
	if cfg.Not != nil {
		cond.Not = convertConditionConfig(cfg.Not)
	}

	return cond
}

// CheckCommandWithContext evaluates a command with taint awareness.
func (ce *ContextEngine) CheckCommandWithContext(ctx context.Context, pid int, command string, args []string) Decision {
	// 1. Check if process is tainted
	taint := ce.taintCache.IsTainted(pid)
	if taint == nil {
		// Not tainted - use normal policy
		return ce.Engine.CheckCommand(command, args)
	}

	// 2. Validate taint (race protection)
	validationResult := ce.validateTaint(taint)
	if validationResult != ancestry.ValidationValid {
		return ce.handleRaceCondition(validationResult, taint, command, args)
	}

	// 3. Find the process context
	pctx := ce.findContext(taint.ContextName)
	if pctx == nil {
		// No context found - use normal policy
		return ce.Engine.CheckCommand(command, args)
	}

	// 4. Build execution context for chain evaluation
	execCtx := &ancestry.ExecutionContext{
		Comm:    filepath.Base(command),
		Args:    args,
		ExePath: command,
	}

	// 5. Evaluate chain rules first (escape hatches, shell laundering detection)
	if pctx.chainEvaluator != nil {
		matchedRules, finalAction := pctx.chainEvaluator.EvaluateWithContinue(taint, execCtx)

		// Handle actions from chain rules
		for _, rule := range matchedRules {
			switch rule.Action {
			case ancestry.ActionMarkAsAgent:
				// Mark process as agent in cache and update local taint copy
				ce.taintCache.MarkAsAgent(pid)
				taint.IsAgent = true
			}
		}

		// If agent was marked, re-evaluate rules with updated taint to catch agent-specific rules
		if taint.IsAgent {
			// Re-evaluate to check if agent-specific rules now apply
			matchedRules, finalAction = pctx.chainEvaluator.EvaluateWithContinue(taint, execCtx)
		}

		// Handle final action
		switch finalAction {
		case ancestry.ActionAllowNormalPolicy:
			// Escape hatch - use normal policy
			return ce.Engine.CheckCommand(command, args)
		case ancestry.ActionDeny:
			lastRule := matchedRules[len(matchedRules)-1]
			return Decision{
				PolicyDecision:    types.DecisionDeny,
				EffectiveDecision: types.DecisionDeny,
				Rule:              "chain:" + lastRule.Name,
				Message:           lastRule.Message,
			}
		case ancestry.ActionApprove:
			lastRule := matchedRules[len(matchedRules)-1]
			return ce.wrapDecision("approve", "chain:"+lastRule.Name, lastRule.Message, nil)
		case ancestry.ActionAllow:
			lastRule := matchedRules[len(matchedRules)-1]
			return Decision{
				PolicyDecision:    types.DecisionAllow,
				EffectiveDecision: types.DecisionAllow,
				Rule:              "chain:" + lastRule.Name,
				Message:           lastRule.Message,
			}
		case ancestry.ActionApplyContextPolicy:
			// Continue to context policy evaluation below
		}
	}

	// 6. Evaluate context-specific policy
	return ce.evaluateContextPolicy(pctx, command, args)
}

// validateTaint checks if the taint data is still valid.
// Returns the validation result for detailed race policy handling.
func (ce *ContextEngine) validateTaint(taint *ancestry.ProcessTaint) ancestry.ValidationResult {
	// Validate source snapshot if available (non-zero snapshot has a StartTime)
	if taint.SourceSnapshot.StartTime != 0 {
		return ancestry.ValidateSnapshotDetailed(taint.SourcePID, &taint.SourceSnapshot)
	}
	// No snapshot to validate - trust cached data
	return ancestry.ValidationValid
}

// handleRaceCondition handles the case where taint validation fails.
func (ce *ContextEngine) handleRaceCondition(validationResult ancestry.ValidationResult, taint *ancestry.ProcessTaint, command string, args []string) Decision {
	pctx := ce.findContext(taint.ContextName)
	if pctx == nil {
		return ce.Engine.CheckCommand(command, args)
	}

	racePolicy := pctx.config.RacePolicy
	if racePolicy == nil {
		// Default: deny on race condition
		return Decision{
			PolicyDecision:    types.DecisionDeny,
			EffectiveDecision: types.DecisionDeny,
			Rule:              "race-condition",
			Message:           "taint validation failed",
		}
	}

	// Select the appropriate action based on validation result
	var action string
	var message string
	switch validationResult {
	case ancestry.ValidationMissing:
		action = racePolicy.OnMissingParent
		message = "parent process data unavailable"
	case ancestry.ValidationPIDMismatch:
		action = racePolicy.OnPIDMismatch
		message = "PID was reused by a different process"
	case ancestry.ValidationError:
		action = racePolicy.OnValidationError
		message = "error validating process ancestry"
	default:
		action = "deny"
		message = "unknown validation failure"
	}

	if action == "" {
		action = "deny"
	}

	switch strings.ToLower(action) {
	case "allow":
		return ce.Engine.CheckCommand(command, args)
	case "approve":
		return Decision{
			PolicyDecision:    types.DecisionApprove,
			EffectiveDecision: types.DecisionApprove,
			Rule:              "race-condition",
			Message:           message,
			Approval:          &types.ApprovalInfo{Required: true, Mode: types.ApprovalModeEnforced},
		}
	default: // deny
		return Decision{
			PolicyDecision:    types.DecisionDeny,
			EffectiveDecision: types.DecisionDeny,
			Rule:              "race-condition",
			Message:           message,
		}
	}
}

// findContext looks up a compiled context by name.
func (ce *ContextEngine) findContext(name string) *compiledContext {
	if name == "" {
		return nil
	}
	return ce.contexts[name]
}

// evaluateContextPolicy evaluates the context-specific policy rules.
func (ce *ContextEngine) evaluateContextPolicy(pctx *compiledContext, command string, args []string) Decision {
	cmdBase := strings.ToLower(filepath.Base(command))
	// Build full command string for matching patterns like "git status"
	fullCmd := cmdBase
	if len(args) > 0 {
		fullCmd = cmdBase + " " + strings.Join(args, " ")
	}
	fullCmdLower := strings.ToLower(fullCmd)

	// 1. Check denied commands first (deny always wins)
	for _, g := range pctx.deniedCmds {
		if g.Match(cmdBase) || g.Match(strings.ToLower(command)) || g.Match(fullCmdLower) {
			return Decision{
				PolicyDecision:    types.DecisionDeny,
				EffectiveDecision: types.DecisionDeny,
				Rule:              "context:denied_commands",
				Message:           fmt.Sprintf("command %q denied in this context", cmdBase),
			}
		}
	}

	// 2. Check command overrides for argument filtering
	if override, ok := pctx.overrides[cmdBase]; ok {
		dec := ce.evaluateOverride(override, command, args)
		if dec != nil {
			return *dec
		}
	}

	// 3. Check require approval commands
	for _, g := range pctx.requireApproval {
		if g.Match(cmdBase) || g.Match(strings.ToLower(command)) || g.Match(fullCmdLower) {
			return ce.wrapDecision("approve", "context:require_approval", "", nil)
		}
	}

	// 4. Check allowed commands
	for _, g := range pctx.allowedCmds {
		if g.Match(cmdBase) || g.Match(strings.ToLower(command)) || g.Match(fullCmdLower) {
			return Decision{
				PolicyDecision:    types.DecisionAllow,
				EffectiveDecision: types.DecisionAllow,
				Rule:              "context:allowed_commands",
			}
		}
	}

	// 5. Check context-specific command rules if defined
	if len(pctx.config.CommandRules) > 0 {
		// Create a temporary engine with context rules
		tempPolicy := &Policy{
			Version:      1,
			Name:         "context",
			CommandRules: pctx.config.CommandRules,
		}
		tempEngine, err := NewEngine(tempPolicy, ce.enforceApprovals)
		if err == nil {
			dec := tempEngine.CheckCommand(command, args)
			// Only return if it's not the default deny
			if dec.Rule != "default-deny-commands" {
				return dec
			}
		}
	}

	// 6. Apply default decision
	defaultDec := strings.ToLower(pctx.config.DefaultDecision)
	if defaultDec == "" {
		defaultDec = "deny" // Safe default
	}

	switch defaultDec {
	case "allow":
		return Decision{
			PolicyDecision:    types.DecisionAllow,
			EffectiveDecision: types.DecisionAllow,
			Rule:              "context:default",
		}
	case "approve":
		return ce.wrapDecision("approve", "context:default", "", nil)
	default: // deny
		return Decision{
			PolicyDecision:    types.DecisionDeny,
			EffectiveDecision: types.DecisionDeny,
			Rule:              "context:default",
			Message:           "command not allowed in this context",
		}
	}
}

// evaluateOverride checks command-specific argument patterns.
func (ce *ContextEngine) evaluateOverride(override *compiledOverride, command string, args []string) *Decision {
	argsJoined := strings.Join(args, " ")

	// Check deny patterns first
	for _, g := range override.argsDeny {
		if g.Match(argsJoined) {
			return &Decision{
				PolicyDecision:    types.DecisionDeny,
				EffectiveDecision: types.DecisionDeny,
				Rule:              "context:override:args_deny",
				Message:           fmt.Sprintf("argument pattern denied for %s", filepath.Base(command)),
			}
		}
		// Also check individual args
		for _, arg := range args {
			if g.Match(arg) {
				return &Decision{
					PolicyDecision:    types.DecisionDeny,
					EffectiveDecision: types.DecisionDeny,
					Rule:              "context:override:args_deny",
					Message:           fmt.Sprintf("argument %q denied for %s", arg, filepath.Base(command)),
				}
			}
		}
	}

	// Check allow patterns
	for _, g := range override.argsAllow {
		if g.Match(argsJoined) {
			return &Decision{
				PolicyDecision:    types.DecisionAllow,
				EffectiveDecision: types.DecisionAllow,
				Rule:              "context:override:args_allow",
			}
		}
		for _, arg := range args {
			if g.Match(arg) {
				return &Decision{
					PolicyDecision:    types.DecisionAllow,
					EffectiveDecision: types.DecisionAllow,
					Rule:              "context:override:args_allow",
				}
			}
		}
	}

	// Apply override default if specified
	if override.defDecision != "" {
		switch strings.ToLower(override.defDecision) {
		case "allow":
			return &Decision{
				PolicyDecision:    types.DecisionAllow,
				EffectiveDecision: types.DecisionAllow,
				Rule:              "context:override:default",
			}
		case "deny":
			return &Decision{
				PolicyDecision:    types.DecisionDeny,
				EffectiveDecision: types.DecisionDeny,
				Rule:              "context:override:default",
			}
		case "approve":
			dec := ce.wrapDecision("approve", "context:override:default", "", nil)
			return &dec
		}
	}

	// No decision from override - continue to other rules
	return nil
}

// TaintCache returns the taint cache for external access.
func (ce *ContextEngine) TaintCache() *ancestry.TaintCache {
	return ce.taintCache
}

// Matcher returns the process matcher for external access.
func (ce *ContextEngine) Matcher() *identity.ProcessMatcher {
	return ce.matcher
}
