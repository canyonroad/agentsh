//go:build !linux

package capabilities

// SecurityCapabilities holds detected security primitive availability.
type SecurityCapabilities struct {
	Seccomp         bool // seccomp-bpf + user-notify
	SeccompBasic    bool // seccomp-bpf without user-notify
	Landlock        bool // any Landlock support
	LandlockABI     int  // 1-5, determines features
	LandlockNetwork bool // ABI v4+, kernel 6.7+
	eBPF            bool // network monitoring
	FUSE            bool // filesystem interception
	Capabilities    bool // can drop capabilities (always true)
	PIDNamespace    bool // isolated PID namespace
}

// SecurityMode represents the security enforcement mode.
const (
	ModeFull         = "full"
	ModeLandlock     = "landlock"
	ModeLandlockOnly = "landlock-only"
	ModeMinimal      = "minimal"
)

// DetectSecurityCapabilities returns minimal capabilities on non-Linux.
func DetectSecurityCapabilities() *SecurityCapabilities {
	return &SecurityCapabilities{
		Capabilities: true, // Can conceptually drop capabilities
	}
}

// SelectMode returns the best available security mode based on capabilities.
func (c *SecurityCapabilities) SelectMode() string {
	// Full mode: all features available
	if c.Seccomp && c.eBPF && c.FUSE {
		return ModeFull
	}

	// Landlock mode: Landlock + FUSE (no seccomp)
	if c.Landlock && c.FUSE {
		return ModeLandlock
	}

	// Landlock-only: just Landlock (no FUSE either)
	if c.Landlock {
		return ModeLandlockOnly
	}

	// Minimal: only capabilities dropping
	return ModeMinimal
}
