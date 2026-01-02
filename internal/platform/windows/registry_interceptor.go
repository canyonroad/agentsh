//go:build windows

package windows

import (
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/pkg/types"
)

// RegistryInterceptor handles registry policy enforcement.
type RegistryInterceptor struct {
	evaluator *RegistryPolicyEvaluator
	emitter   *RegistryEventEmitter
}

// NewRegistryInterceptor creates a new registry interceptor.
func NewRegistryInterceptor(
	cfg *config.RegistryPolicyConfig,
	eventChan chan<- types.Event,
	sessionID string,
) (*RegistryInterceptor, error) {
	eval, err := NewRegistryPolicyEvaluator(cfg)
	if err != nil {
		return nil, err
	}

	return &RegistryInterceptor{
		evaluator: eval,
		emitter:   NewRegistryEventEmitter(eventChan, sessionID),
	}, nil
}

// HandleRequest evaluates a registry request and returns the decision.
// This method is designed to be used as the RegistryPolicyHandler callback.
func (i *RegistryInterceptor) HandleRequest(req *RegistryRequest) (PolicyDecision, uint32) {
	resp := i.evaluator.Evaluate(req)

	// Emit event if logging is enabled
	if resp.LogEvent || resp.Notify || resp.Decision == DecisionDeny {
		i.emitter.EmitRegistryEvent(req, resp, "")
	}

	return resp.Decision, resp.CacheTTL
}

// PolicyHandler returns a handler function suitable for DriverClient.
func (i *RegistryInterceptor) PolicyHandler() RegistryPolicyHandler {
	return i.HandleRequest
}
