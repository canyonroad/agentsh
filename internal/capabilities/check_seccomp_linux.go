//go:build linux

package capabilities

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// probeSeccompBasic checks whether the seccomp() syscall supports BPF filtering
// by querying SECCOMP_GET_ACTION_AVAIL for SECCOMP_RET_KILL_PROCESS.
// This is a read-only probe — no filter is installed.
func probeSeccompBasic() ProbeResult {
	action := uint32(unix.SECCOMP_RET_KILL_PROCESS)
	_, _, errno := unix.Syscall(
		unix.SYS_SECCOMP,
		unix.SECCOMP_GET_ACTION_AVAIL, // op = 2
		0,
		uintptr(unsafe.Pointer(&action)),
	)
	switch errno {
	case 0:
		return ProbeResult{Available: true, Detail: "seccomp-bpf"}
	case unix.ENOSYS:
		return ProbeResult{Available: false, Detail: "ENOSYS (seccomp syscall not available)"}
	case unix.EPERM:
		// Seccomp syscall exists but is blocked (e.g. by outer seccomp filter).
		// The kernel supports it; the runtime blocks it.
		return ProbeResult{Available: false, Detail: "EPERM (seccomp blocked by runtime)"}
	default:
		return ProbeResult{Available: false, Detail: fmt.Sprintf("%s (errno %d)", errno, errno)}
	}
}

// seccompNotifSizes mirrors struct seccomp_notif_sizes from <linux/seccomp.h>.
type seccompNotifSizes struct {
	Notif     uint16
	NotifResp uint16
	Data      uint16
}

// probeSeccompUserNotify checks whether the kernel supports seccomp user-notify
// by calling seccomp(SECCOMP_GET_NOTIF_SIZES). This is a read-only probe.
func probeSeccompUserNotify() ProbeResult {
	var sizes seccompNotifSizes
	_, _, errno := unix.Syscall(
		unix.SYS_SECCOMP,
		unix.SECCOMP_GET_NOTIF_SIZES, // op = 3
		0,
		uintptr(unsafe.Pointer(&sizes)),
	)
	switch errno {
	case 0:
		return ProbeResult{Available: true, Detail: "user-notify"}
	case unix.ENOSYS:
		return ProbeResult{Available: false, Detail: "ENOSYS (seccomp syscall not available)"}
	case unix.EINVAL:
		return ProbeResult{Available: false, Detail: "EINVAL (user-notify not supported, kernel < 5.0)"}
	case unix.EPERM:
		return ProbeResult{Available: false, Detail: "EPERM (seccomp blocked by runtime)"}
	default:
		return ProbeResult{Available: false, Detail: fmt.Sprintf("%s (errno %d)", errno, errno)}
	}
}
