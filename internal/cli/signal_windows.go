//go:build windows

package cli

import (
	"os"
)

// signalsToNotify returns the signals to listen for in PTY mode.
// On Windows, we only handle Interrupt (Ctrl+C).
func signalsToNotify() []os.Signal {
	return []os.Signal{os.Interrupt}
}

// isWinchSignal returns true if the signal is SIGWINCH (window size change).
// Windows doesn't have SIGWINCH - window resize is handled differently via ConPTY.
func isWinchSignal(sig os.Signal) bool {
	return false
}

// signalName returns the name of a signal for sending to the server.
func signalName(sig os.Signal) string {
	switch sig {
	case os.Interrupt:
		return "SIGINT"
	default:
		return ""
	}
}
