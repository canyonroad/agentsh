//go:build linux

package capabilities

import (
	"os/exec"
	"time"

	"golang.org/x/sys/unix"
)

// SecurityCapabilities holds detected security primitive availability.
type SecurityCapabilities struct {
	Seccomp         bool   // seccomp-bpf + user-notify
	SeccompBasic    bool   // seccomp-bpf without user-notify
	Landlock        bool   // any Landlock support
	LandlockABI     int    // 1-5, determines features
	LandlockNetwork bool   // ABI v4+, kernel 6.7+
	EBPF            bool   // network monitoring
	FUSE            bool   // filesystem interception
	Capabilities    bool   // can drop capabilities (always true)
	PIDNamespace    bool   // isolated PID namespace
	Ptrace          bool   // SYS_PTRACE capability available
	PtraceEnabled   bool   // ptrace enforcement enabled in config
	FileEnforcement string // "landlock", "fuse", "seccomp-notify", "none"

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

// DetectSecurityCapabilities probes the system for available security primitives.
func DetectSecurityCapabilities() *SecurityCapabilities {
	caps := &SecurityCapabilities{}

	// Detect Landlock
	llResult := DetectLandlock()
	caps.Landlock = llResult.Available
	caps.LandlockABI = llResult.ABI
	caps.LandlockNetwork = llResult.NetworkSupport

	// Detect other capabilities via probes
	caps.Seccomp = checkSeccompUserNotify().Available
	caps.SeccompBasic = checkSeccompBasic()
	caps.FUSE = checkFUSE()
	caps.Ptrace = checkPtraceCapability()

	// Run real probes and cache results
	ebpfProbe := probeEBPF()
	cgroupProbe := probeCgroupsV2()
	pidnsProbe := probePIDNamespace()
	capProbe := probeCapabilityDrop()

	caps.EBPF = ebpfProbe.Available
	caps.PIDNamespace = pidnsProbe.Available
	caps.Capabilities = capProbe.Available
	caps.EBPFProbe = ebpfProbe
	caps.CgroupProbe = cgroupProbe
	caps.PIDNSProbe = pidnsProbe
	caps.CapProbe = capProbe

	return caps
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

// checkSeccompBasic checks if basic seccomp-bpf is available (without user-notify).
func checkSeccompBasic() bool {
	// For now, assume basic seccomp is available if full seccomp is available
	// A more thorough check could probe for SECCOMP_SET_MODE_FILTER
	return checkSeccompUserNotify().Available
}

func checkFUSE() bool {
	fd, err := unix.Open("/dev/fuse", unix.O_RDWR, 0)
	if err != nil {
		return false
	}
	unix.Close(fd)

	// Priority 1: fusermount
	if hasFusermount() {
		return true
	}

	// Priority 2: new mount API (fsopen probe)
	if checkNewMountAPIAvailable() {
		return true
	}

	// Priority 3: direct mount
	return checkDirectMount()
}

// checkNewMountAPIAvailable probes for new mount API support via fsopen.
func checkNewMountAPIAvailable() bool {
	fd, err := unix.Fsopen("fuse", 0)
	if err != nil {
		return false
	}
	unix.Close(fd)
	return true
}

// hasFusermount checks if the fusermount suid binary is available in PATH.
func hasFusermount() bool {
	for _, name := range []string{"fusermount3", "fusermount"} {
		if _, err := exec.LookPath(name); err == nil {
			return true
		}
	}
	return false
}

// checkDirectMount checks if direct mount() is possible (CAP_SYS_ADMIN + unblocked syscall).
func checkDirectMount() bool {
	// Check for CAP_SYS_ADMIN in the effective capability set
	hdr := &unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := &unix.CapUserData{}
	if err := unix.Capget(hdr, data); err != nil {
		return false
	}
	const capSysAdmin = unix.CAP_SYS_ADMIN
	if data.Effective&(1<<uint(capSysAdmin)) == 0 {
		return false
	}

	// Probe mount() syscall to detect seccomp blocking.
	// Environments like Firecracker have CAP_SYS_ADMIN and /dev/fuse but
	// seccomp blocks mount(). Since we verified CAP_SYS_ADMIN above,
	// EPERM here can only mean seccomp is blocking it.
	return probeMountSyscall()
}

// probeMountSyscall attempts a harmless mount() call with invalid parameters
// to detect whether seccomp is blocking the syscall.
// Returns true if mount() is allowed (even though it fails with expected errors).
func probeMountSyscall() bool {
	type result struct {
		err error
	}
	ch := make(chan result, 1)
	go func() {
		err := unix.Mount("", "", "agentsh-probe", 0, "")
		ch <- result{err: err}
	}()

	select {
	case r := <-ch:
		// EPERM with CAP_SYS_ADMIN means seccomp is blocking mount()
		if r.err == unix.EPERM {
			return false
		}
		// ENODEV, EINVAL, etc. = mount syscall is allowed (just bad params)
		return true
	case <-time.After(500 * time.Millisecond):
		// Timed out — mount() is blocked/hanging
		return false
	}
}

