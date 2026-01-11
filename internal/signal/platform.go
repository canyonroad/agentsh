//go:build !windows

package signal

import "sync"

var (
	canBlockSignals     bool
	canBlockSignalsOnce sync.Once
)

// CanBlockSignals returns true if the platform can block signals.
// This is a runtime check that verifies seccomp user-notify is available.
func CanBlockSignals() bool {
	canBlockSignalsOnce.Do(func() {
		canBlockSignals = IsSignalSupportAvailable()
	})
	return canBlockSignals
}
