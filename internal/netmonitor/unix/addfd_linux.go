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

// ioctlNotifIDValid ioctl numbers for SECCOMP_IOCTL_NOTIF_ID_VALID.
// The kernel changed from _IOW to _IOWR in 5.17 (commit 47e33c05f9f07).
const (
	ioctlNotifIDValidNew = 0xC0082102 // _IOWR('!', 2, __u64) — kernel 5.17+
	ioctlNotifIDValidOld = 0x40082102 // _IOW('!', 2, __u64) — pre-5.17
)

// NotifAddFD injects srcFD from the supervisor process into the trapped
// process's fd table via the seccomp notify fd.
//
// Parameters:
//   - notifFD: the seccomp notify file descriptor
//   - notifID: the notification ID from the trapped syscall
//   - srcFD: the file descriptor in the supervisor to inject
//   - targetFD: the desired fd number in the tracee (only used when SECCOMP_ADDFD_FLAG_SETFD is set;
//     otherwise set to 0 and the kernel will choose)
//   - flags: SECCOMP_ADDFD_FLAG_* flags
//
// Returns the fd number allocated in the tracee, or an error.
func NotifAddFD(notifFD int, notifID uint64, srcFD int, targetFD int, flags uint32) (int, error) {
	// When SETFD is not set, newfd must be 0 (kernel chooses).
	// When SETFD is set, targetFD must be non-negative.
	newfd := uint32(0)
	if flags&SECCOMP_ADDFD_FLAG_SETFD != 0 {
		if targetFD < 0 {
			return -1, fmt.Errorf("SECCOMP_IOCTL_NOTIF_ADDFD: targetFD must be >= 0 when SETFD flag is set")
		}
		newfd = uint32(targetFD)
	}

	req := seccompNotifAddFD{
		id:         notifID,
		flags:      flags,
		srcfd:      uint32(srcFD),
		newfd:      newfd,
		newfdFlags: 0, // default: no flags on injected fd
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

// ProbeAddFDSupport checks if the kernel supports SECCOMP_IOCTL_NOTIF_ADDFD.
// Returns true if supported (Linux 5.9+ with SEND flag support in 5.14+).
// This is a best-effort probe: it tries the ioctl with an invalid fd and
// checks the error. EBADF means the ioctl is recognized; ENOTTY means not.
func ProbeAddFDSupport() bool {
	req := seccompNotifAddFD{}
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(0xFFFFFFFF), // invalid fd
		uintptr(ioctlNotifAddFD),
		uintptr(unsafe.Pointer(&req)),
	)
	// EBADF = kernel knows the ioctl but fd is invalid → supported
	// ENOTTY = kernel doesn't know this ioctl → not supported
	return errno != unix.ENOTTY
}

// NotifIDValid checks whether a seccomp notification ID is still valid
// (the target process/thread hasn't exited or been killed since the
// notification was received). Returns nil if valid, ENOENT if stale.
//
// Tries the 5.17+ ioctl first, falls back to pre-5.17 on ENOTTY.
func NotifIDValid(notifFD int, notifID uint64) error {
	id := notifID
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(notifFD),
		uintptr(ioctlNotifIDValidNew),
		uintptr(unsafe.Pointer(&id)),
	)
	if errno == unix.ENOTTY {
		_, _, errno = unix.Syscall(
			unix.SYS_IOCTL,
			uintptr(notifFD),
			uintptr(ioctlNotifIDValidOld),
			uintptr(unsafe.Pointer(&id)),
		)
	}
	if errno != 0 {
		return errno
	}
	return nil
}
