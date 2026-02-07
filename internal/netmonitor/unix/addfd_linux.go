//go:build linux && cgo

package unix

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// SECCOMP_ADDFD_FLAG_* constants from <linux/seccomp.h>.
const (
	// SECCOMP_ADDFD_FLAG_SETFD places the fd at newfd in the tracee
	// (equivalent to dup2 semantics).
	SECCOMP_ADDFD_FLAG_SETFD = 0x1

	// SECCOMP_ADDFD_FLAG_SEND atomically adds the fd AND returns from the
	// notification, avoiding a TOCTOU race between addfd and respond.
	SECCOMP_ADDFD_FLAG_SEND = 0x2
)

// seccompNotifAddFD matches struct seccomp_notif_addfd from <linux/seccomp.h>.
// The layout must exactly mirror the kernel struct:
//
//	struct seccomp_notif_addfd {
//	    __u64 id;
//	    __u32 flags;
//	    __u32 srcfd;
//	    __u32 newfd;
//	    __u32 newfd_flags;
//	};
type seccompNotifAddFD struct {
	id         uint64 // notification ID from seccomp_notif_req
	flags      uint32 // SECCOMP_ADDFD_FLAG_*
	srcfd      uint32 // fd in supervisor's fd table
	newfd      uint32 // target fd in tracee (when SETFD flag is set)
	newfdFlags uint32 // file flags for the new fd (e.g., O_CLOEXEC)
}

// ioctlNotifAddFD is the ioctl number for SECCOMP_IOCTL_NOTIF_ADDFD.
// Computed as _IOW('!', 3, struct seccomp_notif_addfd) = 0x40182103.
const ioctlNotifAddFD = 0x40182103

// NotifAddFD injects srcFD from the supervisor process into the trapped
// process's fd table via the seccomp notify fd.
//
// Parameters:
//   - notifFD: the seccomp notify file descriptor
//   - notifID: the notification ID from the trapped syscall
//   - srcFD: the file descriptor in the supervisor to inject
//   - targetFD: the desired fd number in the tracee (-1 to let the kernel choose)
//   - flags: SECCOMP_ADDFD_FLAG_* flags
//
// Returns the fd number allocated in the tracee, or an error.
func NotifAddFD(notifFD int, notifID uint64, srcFD int, targetFD int, flags uint32) (int, error) {
	req := seccompNotifAddFD{
		id:         notifID,
		flags:      flags,
		srcfd:      uint32(srcFD),
		newfd:      uint32(targetFD),
		newfdFlags: 0,
	}

	r1, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(notifFD),
		uintptr(ioctlNotifAddFD),
		uintptr(unsafe.Pointer(&req)),
	)
	if errno != 0 {
		return -1, fmt.Errorf("SECCOMP_IOCTL_NOTIF_ADDFD: %w", errno)
	}
	return int(r1), nil
}
