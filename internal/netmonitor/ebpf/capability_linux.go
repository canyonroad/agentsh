//go:build linux

package ebpf

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

// SupportStatus describes whether eBPF tracing is usable on this host.
type SupportStatus struct {
	Supported bool
	Reason    string
}

// CheckSupport performs lightweight capability checks for cgroup eBPF network tracing.
// It avoids loading any program; callers should still handle attach-time errors.
func CheckSupport() SupportStatus {
	if runtime.GOOS != "linux" {
		return SupportStatus{Supported: false, Reason: "not linux"}
	}

	// cgroup v2 must be mounted. cgroup.controllers is the canonical marker
	// — cgroup v1 hierarchies do not expose it at the unified mount point.
	//
	// We intentionally do NOT grep this file for "bpf": BPF is not a
	// cgroup v2 resource controller. cgroup.controllers enumerates
	// resource controllers (cpu, memory, io, pids, cpuset, …) as defined
	// in include/linux/cgroup_subsys.h; none of them is "bpf". cgroup BPF
	// programs are attached via BPF_PROG_ATTACH/BPF_LINK_CREATE, gated by
	// the CONFIG_CGROUP_BPF kernel build option. There is no runtime file
	// that directly advertises CONFIG_CGROUP_BPF, so callers rely on the
	// BPF_PROG_LOAD canary in probeEBPF — loading a
	// BPF_PROG_TYPE_CGROUP_SOCK_ADDR program implicitly fails on kernels
	// without CGROUP_BPF support. The previous "strings.Contains(…, \"bpf\")"
	// check was a dead-man's switch: it never passed on any Linux system
	// (including CI runners), which caused CheckSupport to report
	// "cgroup bpf controller not available" universally and silently
	// skipped the integration tests that would have caught #196.
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		return SupportStatus{Supported: false, Reason: "cgroup v2 not available"}
	}

	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		if _, dirErr := os.Stat("/sys/kernel/btf"); dirErr != nil {
			return SupportStatus{Supported: false, Reason: "btf not present (missing /sys/kernel/btf/vmlinux)"}
		}
	}

	if !hasCap(unix.CAP_BPF) && !hasCap(unix.CAP_SYS_ADMIN) {
		return SupportStatus{Supported: false, Reason: "missing CAP_BPF or CAP_SYS_ADMIN"}
	}

	major, minor, err := kernelVersion()
	if err != nil {
		return SupportStatus{Supported: false, Reason: "kernel version unknown"}
	}
	if major < 5 || (major == 5 && minor < 8) {
		return SupportStatus{Supported: false, Reason: fmt.Sprintf("kernel %d.%d < 5.8", major, minor)}
	}

	// Warn (but do not fail) on potential lockdown/LSM restrictions; attach may still fail.
	// We keep this informational to avoid false negatives on permissive systems.
	// Caller should surface attach-time errors explicitly.

	return SupportStatus{Supported: true}
}

// hasCap reports whether the effective capability set contains cap. It
// handles the full 64-bit V3 capability mask — earlier revisions of this
// helper only read the low 32 bits of Effective, which always returned
// false for CAP_BPF (bit 39), CAP_PERFMON (bit 38), and any other high
// capability. LINUX_CAPABILITY_VERSION_3 requires a two-element
// CapUserData array; passing a single struct is the Go footgun tracked
// in golang/go#44312 and writes past the end of the user-allocated
// buffer (the kernel copies 2 * sizeof(CapUserData) regardless).
func hasCap(cap int) bool {
	hdr := &unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(hdr, &data[0]); err != nil {
		return false
	}
	return capBitSet(data, cap)
}

// capBitSet is a pure helper that returns whether the given capability bit
// is set in the V3 effective mask. Split out from hasCap so regression tests
// can assert the word-selection logic with synthetic data, independent of
// the current process's capabilities.
func capBitSet(data [2]unix.CapUserData, cap int) bool {
	if cap < 0 || cap >= 64 {
		return false
	}
	if cap < 32 {
		return data[0].Effective&(1<<uint(cap)) != 0
	}
	return data[1].Effective&(1<<uint(cap-32)) != 0
}

func kernelVersion() (int, int, error) {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return 0, 0, err
	}
	release := utsToString(uts.Release[:])
	parts := strings.Split(release, ".")
	if len(parts) < 2 {
		return 0, 0, fmt.Errorf("unexpected kernel release: %q", release)
	}
	var maj, min int
	if _, err := fmt.Sscanf(parts[0], "%d", &maj); err != nil {
		return 0, 0, fmt.Errorf("parse major from %q: %w", release, err)
	}
	if _, err := fmt.Sscanf(parts[1], "%d", &min); err != nil {
		return 0, 0, fmt.Errorf("parse minor from %q: %w", release, err)
	}
	return maj, min, nil
}

func utsToString(buf []byte) string {
	n := 0
	for n < len(buf) && buf[n] != 0 {
		n++
	}
	return string(buf[:n])
}
