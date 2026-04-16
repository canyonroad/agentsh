//go:build linux && cgo

package seccomp

// OnBlockAction determines what seccomp does when a block-listed syscall fires.
type OnBlockAction string

const (
	OnBlockErrno      OnBlockAction = "errno"
	OnBlockKill       OnBlockAction = "kill"
	OnBlockLog        OnBlockAction = "log"
	OnBlockLogAndKill OnBlockAction = "log_and_kill"
)

// ParseOnBlock converts a config string to a typed action.
// Empty string maps to OnBlockErrno (the default after applyDefaults runs).
// Unknown strings return OnBlockErrno and false — callers should treat this
// as a defense-in-depth degradation and log a warning.
func ParseOnBlock(s string) (OnBlockAction, bool) {
	switch OnBlockAction(s) {
	case "", OnBlockErrno:
		return OnBlockErrno, true
	case OnBlockKill, OnBlockLog, OnBlockLogAndKill:
		return OnBlockAction(s), true
	default:
		return OnBlockErrno, false
	}
}

// FilterConfig holds settings for building a seccomp filter.
type FilterConfig struct {
	UnixSocketEnabled bool
	BlockedSyscalls   []string
	OnBlock           OnBlockAction
}

// FilterConfigFromYAML creates a FilterConfig from config package types.
// This is a separate function to avoid import cycles.
func FilterConfigFromYAML(unixEnabled bool, blockedSyscalls []string, onBlock string) FilterConfig {
	action, _ := ParseOnBlock(onBlock)
	return FilterConfig{
		UnixSocketEnabled: unixEnabled,
		BlockedSyscalls:   blockedSyscalls,
		OnBlock:           action,
	}
}
