package session

import (
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
)

// PolicyRouter routes policy checks to the appropriate mount's policy engine.
type PolicyRouter struct {
	basePolicy *policy.Engine
	mounts     []ResolvedMount
}

// NewPolicyRouter creates a policy router with base policy and mount-specific policies.
func NewPolicyRouter(basePolicy *policy.Engine, mounts []ResolvedMount) *PolicyRouter {
	return &PolicyRouter{
		basePolicy: basePolicy,
		mounts:     mounts,
	}
}

// CheckFile checks file access against the appropriate mount policy, then base policy.
// The policy layering is:
// 1. If path is not covered by any mount -> deny (unmounted paths blocked)
// 2. If mount policy denies -> deny (mount can restrict)
// 3. If base policy denies -> deny (base policy always applies)
// 4. Otherwise -> allow
// This means mount policies can only restrict what base policy allows, not expand it.
func (r *PolicyRouter) CheckFile(path, op string) policy.Decision {
	mount := FindMount(r.mounts, path)
	if mount == nil {
		// Unmounted path - deny by default
		return policy.Decision{
			PolicyDecision:    types.DecisionDeny,
			EffectiveDecision: types.DecisionDeny,
			Rule:              "unmounted-path",
			Message:           "path is not covered by any mount",
		}
	}

	// Check mount policy first
	if mount.PolicyEngine != nil {
		dec := mount.PolicyEngine.CheckFile(path, op)
		if dec.EffectiveDecision == types.DecisionDeny {
			return dec
		}
	}

	// Check base policy
	if r.basePolicy != nil {
		return r.basePolicy.CheckFile(path, op)
	}

	// No policies - allow
	return policy.Decision{
		PolicyDecision:    types.DecisionAllow,
		EffectiveDecision: types.DecisionAllow,
	}
}

// CheckCommand delegates to base policy (mounts don't affect commands).
func (r *PolicyRouter) CheckCommand(cmd string, args []string) policy.Decision {
	if r.basePolicy != nil {
		return r.basePolicy.CheckCommand(cmd, args)
	}
	return policy.Decision{
		PolicyDecision:    types.DecisionAllow,
		EffectiveDecision: types.DecisionAllow,
	}
}

// CheckNetwork delegates to base policy (mounts don't affect network).
func (r *PolicyRouter) CheckNetwork(domain string, port int) policy.Decision {
	if r.basePolicy != nil {
		return r.basePolicy.CheckNetwork(domain, port)
	}
	return policy.Decision{
		PolicyDecision:    types.DecisionAllow,
		EffectiveDecision: types.DecisionAllow,
	}
}
