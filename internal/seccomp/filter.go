//go:build linux && cgo

package seccomp

// FilterConfig holds settings for building a seccomp filter.
type FilterConfig struct {
	UnixSocketEnabled bool
	BlockedSyscalls   []string
	BlockedFamilies   []BlockedFamily
	OnBlock           OnBlockAction
}

// FilterConfigFromYAML creates a FilterConfig from config package types.
// This is a separate function to avoid import cycles.
func FilterConfigFromYAML(unixEnabled bool, blockedSyscalls []string, onBlock string, blockedFamilies []BlockedFamily) FilterConfig {
	action, _ := ParseOnBlock(onBlock)
	return FilterConfig{
		UnixSocketEnabled: unixEnabled,
		BlockedSyscalls:   blockedSyscalls,
		BlockedFamilies:   blockedFamilies,
		OnBlock:           action,
	}
}
