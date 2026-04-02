//go:build darwin

package policysock

import (
	"fmt"
	"net"
	"os/exec"
	"unsafe"

	"golang.org/x/sys/unix"
)

/*
#include <libproc.h>
#include <sys/proc_info.h>
*/
import "C"

// ValidatePeer checks that a connected Unix socket peer is:
// 1. Running as root (UID 0)
// 2. Signed by the expected team ID
func ValidatePeer(conn *net.UnixConn, teamID string) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("syscall conn: %w", err)
	}

	var peerUID uint32
	var peerPID int32
	var sockErr error

	err = raw.Control(func(fd uintptr) {
		// Layer 2: Peer UID check
		uid, err := getpeereid(int(fd))
		if err != nil {
			sockErr = fmt.Errorf("getpeereid: %w", err)
			return
		}
		peerUID = uid

		// Layer 3: Get peer PID
		pid, err := getPeerPID(int(fd))
		if err != nil {
			sockErr = fmt.Errorf("LOCAL_PEERPID: %w", err)
			return
		}
		peerPID = pid
	})
	if err != nil {
		return fmt.Errorf("control: %w", err)
	}
	if sockErr != nil {
		return sockErr
	}

	// Layer 2: Reject non-root
	if peerUID != 0 {
		return fmt.Errorf("peer UID %d is not root", peerUID)
	}

	// Layer 3: Resolve binary path and validate code signing
	path, err := resolvePIDPath(peerPID)
	if err != nil {
		return fmt.Errorf("resolve pid %d path: %w", peerPID, err)
	}

	if err := validateCodeSignature(path, teamID); err != nil {
		return fmt.Errorf("code signing validation failed for %s (pid %d): %w", path, peerPID, err)
	}

	return nil
}

// LOCAL_PEERPID is the socket option to get the peer's PID on macOS.
const LOCAL_PEERPID = 0x002

// getpeereid returns the effective UID of the peer.
func getpeereid(fd int) (uid uint32, err error) {
	xucred, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return 0, err
	}
	return xucred.Uid, nil
}

// getPeerPID returns the PID of the peer process.
func getPeerPID(fd int) (int32, error) {
	pid, err := unix.GetsockoptInt(fd, unix.SOL_LOCAL, LOCAL_PEERPID)
	if err != nil {
		return 0, err
	}
	return int32(pid), nil
}

// resolvePIDPath returns the executable path for a given PID.
func resolvePIDPath(pid int32) (string, error) {
	var buf [C.PROC_PIDPATHINFO_MAXSIZE]C.char
	ret := C.proc_pidpath(C.int(pid), unsafe.Pointer(&buf[0]), C.uint32_t(len(buf)))
	if ret <= 0 {
		return "", fmt.Errorf("proc_pidpath failed for pid %d", pid)
	}
	return C.GoString(&buf[0]), nil
}

// validateCodeSignature verifies a binary is signed by the expected team ID.
func validateCodeSignature(path string, teamID string) error {
	requirement := fmt.Sprintf(
		`anchor apple generic and certificate leaf[subject.OU] = "%s"`,
		teamID,
	)
	cmd := exec.Command("codesign", "--verify", "-R="+requirement, path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("codesign verification failed: %s: %w", string(output), err)
	}
	return nil
}
