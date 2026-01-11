//go:build windows

package policy

// compileSignalRules is a no-op on Windows (signal interception not supported).
func compileSignalRules(rules []SignalRule) (interface{}, error) {
	return nil, nil
}

// signalEngineType is nil on Windows.
type signalEngineType = interface{}
