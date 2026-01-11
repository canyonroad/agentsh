//go:build windows

package signal

// CanBlockSignals returns false on Windows (signal interception not supported).
func CanBlockSignals() bool {
	return false
}
