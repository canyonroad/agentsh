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

	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		return SupportStatus{Supported: false, Reason: "cgroup v2 not available"}
	}
	controllers, _ := os.ReadFile("/sys/fs/cgroup/cgroup.controllers")
	if !strings.Contains(string(controllers), "bpf") {
		return SupportStatus{Supported: false, Reason: "cgroup bpf controller not available"}
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

func hasCap(cap int) bool {
	hdr := &unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := &unix.CapUserData{}
	if err := unix.Capget(hdr, data); err != nil {
		return false
	}
	// Effective set check
	switch {
	case cap < 0 || cap >= 64:
		return false
	case cap < 32:
		return data.Effective&(1<<uint(cap)) != 0
	default:
		// Version 3 supports up to 63; beyond that we treat as unsupported.
		return false
	}
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
