package platform

import (
	"github.com/agentsh/agentsh/internal/policy"
)

// PolicyAdapter wraps *policy.Engine to implement platform.PolicyEngine.
// This bridges the existing policy engine to the platform abstraction layer.
type PolicyAdapter struct {
	engine *policy.Engine
}

// NewPolicyAdapter creates a new adapter wrapping the given policy engine.
func NewPolicyAdapter(engine *policy.Engine) *PolicyAdapter {
	if engine == nil {
		return nil
	}
	return &PolicyAdapter{engine: engine}
}

// Engine returns the underlying *policy.Engine.
// This is used by platform implementations that need the raw engine.
func (a *PolicyAdapter) Engine() *policy.Engine {
	if a == nil {
		return nil
	}
	return a.engine
}

// CheckFile evaluates file access policy.
func (a *PolicyAdapter) CheckFile(path string, op FileOperation) Decision {
	if a == nil || a.engine == nil {
		return DecisionAllow
	}
	decision := a.engine.CheckFile(path, string(op))
	return decision.EffectiveDecision
}

// CheckNetwork evaluates network access policy.
func (a *PolicyAdapter) CheckNetwork(addr string, port int, protocol string) Decision {
	if a == nil || a.engine == nil {
		return DecisionAllow
	}
	// The policy engine's CheckNetwork takes domain and port
	// Protocol is not currently used by the policy engine
	decision := a.engine.CheckNetwork(addr, port)
	return decision.EffectiveDecision
}

// CheckEnv evaluates environment variable access policy.
func (a *PolicyAdapter) CheckEnv(name string, op EnvOperation) Decision {
	if a == nil || a.engine == nil {
		return DecisionAllow
	}
	decision := a.engine.CheckEnv(name)
	if decision.Allowed {
		return DecisionAllow
	}
	return DecisionDeny
}

// CheckCommand evaluates command execution policy.
func (a *PolicyAdapter) CheckCommand(cmd string, args []string) Decision {
	if a == nil || a.engine == nil {
		return DecisionAllow
	}
	decision := a.engine.CheckCommand(cmd, args)
	return decision.EffectiveDecision
}

// Compile-time interface check
var _ PolicyEngine = (*PolicyAdapter)(nil)
