package xpc

import (
	"log/slog"

	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
)

// SessionResolver looks up session ID for a process.
type SessionResolver interface {
	SessionForPID(pid int32) string
}

// PolicyAdapter adapts the policy.Engine to the PolicyHandler interface.
type PolicyAdapter struct {
	engine   *policy.Engine
	sessions SessionResolver
}

// NewPolicyAdapter creates a new policy adapter.
func NewPolicyAdapter(engine *policy.Engine, sessions SessionResolver) *PolicyAdapter {
	return &PolicyAdapter{
		engine:   engine,
		sessions: sessions,
	}
}

// CheckFile evaluates file access policy.
func (a *PolicyAdapter) CheckFile(path, op string) (allow bool, rule string) {
	if a.engine == nil {
		return true, "no-policy"
	}
	dec := a.engine.CheckFile(path, op)
	return dec.EffectiveDecision == types.DecisionAllow, dec.Rule
}

// CheckNetwork evaluates network access policy.
func (a *PolicyAdapter) CheckNetwork(ip string, port int, domain string) (allow bool, rule string) {
	if a.engine == nil {
		return true, "no-policy"
	}
	// Use domain if provided, otherwise use IP
	target := domain
	if target == "" {
		target = ip
	}
	dec := a.engine.CheckNetwork(target, port)
	return dec.EffectiveDecision == types.DecisionAllow, dec.Rule
}

// CheckCommand evaluates command execution policy.
func (a *PolicyAdapter) CheckCommand(cmd string, args []string) (allow bool, rule string) {
	if a.engine == nil {
		return true, "no-policy"
	}
	dec := a.engine.CheckCommand(cmd, args)
	return dec.EffectiveDecision == types.DecisionAllow, dec.Rule
}

// ResolveSession looks up the session ID for a process.
func (a *PolicyAdapter) ResolveSession(pid int32) string {
	if a.sessions == nil {
		return ""
	}
	return a.sessions.SessionForPID(pid)
}

// CheckExec evaluates a command through the exec pipeline, returning
// the full decision and action for the ESF client to act on.
func (a *PolicyAdapter) CheckExec(executable string, args []string, pid int32, parentPID int32, sessionID string, _ ExecContext) ExecCheckResult {
	if a.engine == nil {
		return ExecCheckResult{
			Decision: "allow",
			Action:   "continue",
			Rule:     "no-policy",
		}
	}

	dec := a.engine.CheckCommand(executable, args)

	// Use PolicyDecision for audit logging (the raw policy intent)
	decision := string(dec.PolicyDecision)

	// Use EffectiveDecision for action mapping (what actually happens, respects shadow mode)
	effectiveDecision := dec.EffectiveDecision
	if effectiveDecision == "" {
		effectiveDecision = dec.PolicyDecision
	}

	var action string
	switch effectiveDecision {
	case types.DecisionAllow, types.DecisionAudit:
		action = "continue"
	case types.DecisionDeny:
		action = "deny"
	case types.DecisionApprove, types.DecisionRedirect:
		action = "redirect"
	case types.DecisionSoftDelete:
		// soft-delete is a file operation concept; for exec, treat as continue
		action = "continue"
	default:
		// Unknown decisions fail-closed to prevent accidental allows.
		slog.Warn("xpc: unknown effective decision in CheckExec, denying",
			"effective_decision", string(effectiveDecision),
			"policy_decision", decision,
			"cmd", executable,
		)
		action = "deny"
	}

	return ExecCheckResult{
		Decision: decision,
		Action:   action,
		Rule:     dec.Rule,
		Message:  dec.Message,
	}
}

// Compile-time interface checks
var _ PolicyHandler = (*PolicyAdapter)(nil)
var _ ExecHandler = (*PolicyAdapter)(nil)
