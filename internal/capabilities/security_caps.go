//go:build linux

package capabilities

import "golang.org/x/sys/unix"

// SecurityCapabilities holds detected security primitive availability.
type SecurityCapabilities struct {
	Seccomp         bool // seccomp-bpf + user-notify
	SeccompBasic    bool // seccomp-bpf without user-notify
	Landlock        bool // any Landlock support
	LandlockABI     int  // 1-5, determines features
	LandlockNetwork bool // ABI v4+, kernel 6.7+
	EBPF            bool // network monitoring
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

// DetectSecurityCapabilities probes the system for available security primitives.
func DetectSecurityCapabilities() *SecurityCapabilities {
	caps := &SecurityCapabilities{
		Capabilities: true, // Can always drop capabilities
	}

	// Detect Landlock
	llResult := DetectLandlock()
	caps.Landlock = llResult.Available
	caps.LandlockABI = llResult.ABI
	caps.LandlockNetwork = llResult.NetworkSupport

	// Detect other capabilities (use existing checks)
	caps.Seccomp = checkSeccompUserNotify().Available
	caps.SeccompBasic = checkSeccompBasic()
	caps.EBPF = checkeBPF().Available
	caps.FUSE = checkFUSE()
	caps.PIDNamespace = checkPIDNamespace()

	return caps
}

// SelectMode returns the best available security mode based on capabilities.
func (c *SecurityCapabilities) SelectMode() string {
	// Full mode: all features available
	if c.Seccomp && c.EBPF && c.FUSE {
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

// checkSeccompBasic checks if basic seccomp-bpf is available (without user-notify).
func checkSeccompBasic() bool {
	// For now, assume basic seccomp is available if full seccomp is available
	// A more thorough check could probe for SECCOMP_SET_MODE_FILTER
	return checkSeccompUserNotify().Available
}

// checkFUSE checks if FUSE is usable for filesystem interception.
// Verifies both /dev/fuse access and CAP_SYS_ADMIN capability.
func checkFUSE() bool {
	// Check that /dev/fuse can be opened (not just that it exists)
	fd, err := unix.Open("/dev/fuse", unix.O_RDWR, 0)
	if err != nil {
		return false
	}
	unix.Close(fd)

	// Check for CAP_SYS_ADMIN in the effective capability set
	hdr := &unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := &unix.CapUserData{}
	if err := unix.Capget(hdr, data); err != nil {
		return false
	}
	const capSysAdmin = unix.CAP_SYS_ADMIN
	return data.Effective&(1<<uint(capSysAdmin)) != 0
}

// checkPIDNamespace checks if we're in a PID namespace (isolated process space).
func checkPIDNamespace() bool {
	// Check if PID 1 is not init/systemd (would indicate PID namespace)
	// For now, return false - we can refine this check later
	return false
}
