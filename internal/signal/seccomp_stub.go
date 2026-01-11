//go:build !linux || !cgo

package signal

import "fmt"

// SignalFilterConfig configures which signal syscalls to intercept.
type SignalFilterConfig struct {
	Enabled  bool
	Syscalls []int
}

// DefaultSignalFilterConfig returns a config for intercepting all signal syscalls.
func DefaultSignalFilterConfig() SignalFilterConfig {
	return SignalFilterConfig{
		Enabled: false,
		Syscalls: nil,
	}
}

// SignalFilter wraps a seccomp filter for signal syscall interception.
type SignalFilter struct{}

// SignalContext holds information extracted from a signal syscall.
type SignalContext struct {
	PID       int // PID of the process making the syscall
	Syscall   int // The syscall number (SYS_KILL, SYS_TGKILL, etc.)
	TargetPID int // Target PID of the signal
	TargetTID int // Target TID (for tgkill/tkill)
	Signal    int // The signal number being sent
}

// IsSignalSupportAvailable checks if seccomp user-notify is available.
func IsSignalSupportAvailable() bool {
	return false
}

// DetectSignalSupport returns an error if seccomp user-notify is not available.
func DetectSignalSupport() error {
	return ErrSignalUnsupported
}

// InstallSignalFilter installs a user-notify seccomp filter for signal syscalls.
func InstallSignalFilter(cfg SignalFilterConfig) (*SignalFilter, error) {
	return nil, ErrSignalUnsupported
}

// NotifFD returns the raw notify file descriptor for polling.
func (f *SignalFilter) NotifFD() int {
	return -1
}

// Close closes the filter's notify file descriptor.
func (f *SignalFilter) Close() error {
	return nil
}

// Receive receives one seccomp notification.
func (f *SignalFilter) Receive() (interface{}, error) {
	return nil, ErrSignalUnsupported
}

// Respond replies to a notification with allow or deny.
func (f *SignalFilter) Respond(reqID uint64, allow bool, errno int32) error {
	return ErrSignalUnsupported
}

// RespondWithValue replies to a notification with a specific return value.
func (f *SignalFilter) RespondWithValue(reqID uint64, val uint64, errno int32) error {
	return ErrSignalUnsupported
}

// ExtractSignalContext extracts signal information from a seccomp notify request.
func ExtractSignalContext(req interface{}) SignalContext {
	return SignalContext{}
}

// IsProcessGroupSignal returns true if the signal targets a process group.
func (c *SignalContext) IsProcessGroupSignal() bool {
	return c.TargetPID <= 0
}

// ProcessGroupID returns the process group ID for process group signals.
func (c *SignalContext) ProcessGroupID() int {
	if c.TargetPID == 0 {
		return c.PID
	}
	if c.TargetPID < 0 {
		return -c.TargetPID
	}
	return 0
}

// ErrSignalUnsupported indicates signal interception is not available.
var ErrSignalUnsupported = fmt.Errorf("signal interception unsupported on this platform")
