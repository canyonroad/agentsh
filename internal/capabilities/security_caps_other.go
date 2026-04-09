//go:build !linux

package capabilities

// SecurityCapabilities holds detected security primitive availability.
//
// Capabilities and CapabilitiesActive mirror the Linux split: Capabilities
// is the mechanism flag (always true where the platform conceptually
// supports capability-style privilege reduction) and CapabilitiesActive is
// the behavioural flag indicating the process itself has durably reduced
// its capability set. Non-Linux platforms do not have a real capability
// probe, so CapabilitiesActive defaults to false until a platform probe
// populates it — callers asking "is privilege reduction protecting this
// process" must use CapabilitiesActive to stay honest about that.
type SecurityCapabilities struct {
	Seccomp            bool   // seccomp-bpf + user-notify
	SeccompBasic       bool   // seccomp-bpf without user-notify
	Landlock           bool   // any Landlock support
	LandlockABI        int    // 1-5, determines features
	LandlockNetwork    bool   // ABI v4+, kernel 6.7+
	EBPF               bool   // network monitoring
	FUSE               bool   // filesystem interception
	Capabilities       bool   // capability-drop mechanism available (always true)
	CapabilitiesActive bool   // capability-drop probe reports this process has durably reduced its capability set
	PIDNamespace       bool   // isolated PID namespace
	Ptrace             bool   // SYS_PTRACE capability available
	PtraceEnabled      bool   // ptrace enforcement enabled in config
	FileEnforcement    string // "landlock", "fuse", "seccomp-notify", "none"

	// Cached probe results (populated by DetectSecurityCapabilities, reused by buildLinuxDomains)
	EBPFProbe   ProbeResult
	CgroupProbe ProbeResult
	PIDNSProbe  ProbeResult
	CapProbe    ProbeResult
}

// SecurityMode represents the security enforcement mode.
const (
	ModeFull         = "full"
	ModePtrace       = "ptrace"
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
	if c.Seccomp && c.EBPF && c.FUSE {
		return ModeFull
	}

	// Ptrace mode: SYS_PTRACE available and enabled
	if c.Ptrace && c.PtraceEnabled {
		return ModePtrace
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
