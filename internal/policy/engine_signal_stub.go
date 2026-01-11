//go:build windows

package policy

import "github.com/agentsh/agentsh/internal/signal"

// compileSignalRules is a no-op on Windows (signal interception not supported).
func compileSignalRules(rules []SignalRule) (*signal.Engine, error) {
	return nil, nil
}

// signalEngineType uses the stub Engine type on Windows.
type signalEngineType = *signal.Engine
