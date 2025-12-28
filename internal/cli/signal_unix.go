//go:build !windows

package cli

import (
	"os"
	"syscall"
)

// signalsToNotify returns the signals to listen for in PTY mode.
func signalsToNotify() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGWINCH}
}

// isWinchSignal returns true if the signal is SIGWINCH (window size change).
func isWinchSignal(sig os.Signal) bool {
	return sig == syscall.SIGWINCH
}

// signalName returns the name of a signal for sending to the server.
func signalName(sig os.Signal) string {
	switch sig {
	case os.Interrupt:
		return "SIGINT"
	case syscall.SIGTERM:
		return "SIGTERM"
	case syscall.SIGHUP:
		return "SIGHUP"
	case syscall.SIGQUIT:
		return "SIGQUIT"
	default:
		return ""
	}
}
