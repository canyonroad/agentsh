//go:build windows

package signal

import "fmt"

// Signal name to number mapping (stub for Windows)
var signalNames = map[string]int{}

// Signal groups for policy convenience (stub for Windows)
var signalGroups = map[string][]int{}

// SignalFromString converts a signal name or number to its numeric value.
func SignalFromString(s string) (int, error) {
	return 0, fmt.Errorf("signals not supported on Windows")
}

// SignalName returns the name of a signal number.
func SignalName(sig int) string {
	return fmt.Sprintf("SIG%d", sig)
}

// ExpandSignalGroup expands a signal group to its signal numbers.
func ExpandSignalGroup(group string) ([]int, error) {
	return nil, fmt.Errorf("signals not supported on Windows")
}

// IsSignalGroup returns true if the string is a signal group.
func IsSignalGroup(s string) bool {
	return false
}

// AllSignals returns all signal numbers.
func AllSignals() []int {
	return nil
}
