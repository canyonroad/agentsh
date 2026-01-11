//go:build !windows

package policy

import (
	"fmt"

	"github.com/agentsh/agentsh/internal/signal"
)

// compileSignalRules compiles signal rules into a signal engine.
func compileSignalRules(rules []SignalRule) (*signal.Engine, error) {
	if len(rules) == 0 {
		return nil, nil
	}

	// Convert policy.SignalRule to signal.SignalRule to avoid import cycle
	sigRules := make([]signal.SignalRule, len(rules))
	for i, r := range rules {
		sigRules[i] = signal.SignalRule{
			Name:        r.Name,
			Description: r.Description,
			Signals:     r.Signals,
			Target: signal.TargetSpec{
				Type:    r.Target.Type,
				Pattern: r.Target.Pattern,
				Min:     r.Target.Min,
				Max:     r.Target.Max,
			},
			Decision:   r.Decision,
			Fallback:   r.Fallback,
			RedirectTo: r.RedirectTo,
			Message:    r.Message,
		}
	}
	sigEngine, err := signal.NewEngine(sigRules)
	if err != nil {
		return nil, fmt.Errorf("compile signal rules: %w", err)
	}
	return sigEngine, nil
}

// signalEngineType is the concrete type for the signal engine.
type signalEngineType = *signal.Engine
