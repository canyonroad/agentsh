//go:build linux

package postgres

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// readPeerCred returns the peer's uid and pid via SO_PEERCRED on a Unix
// socket connection. Returns an error if conn is not a *net.UnixConn or the
// getsockopt call fails.
//
// Spec §12.5: SO_PEERCRED is the listener-auth primitive in Plan 04a.
// Plan 07 hardens this to a SessionID resolution via the ptrace registry.
func readPeerCred(conn net.Conn) (uid uint32, pid int32, err error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, 0, fmt.Errorf("readPeerCred: conn is %T, want *net.UnixConn", conn)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, 0, fmt.Errorf("readPeerCred: SyscallConn: %w", err)
	}
	var ucred *unix.Ucred
	var sysErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		ucred, sysErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if ctrlErr != nil {
		return 0, 0, fmt.Errorf("readPeerCred: Control: %w", ctrlErr)
	}
	if sysErr != nil {
		return 0, 0, fmt.Errorf("readPeerCred: SO_PEERCRED: %w", sysErr)
	}
	if ucred == nil {
		return 0, 0, errors.New("readPeerCred: ucred is nil")
	}
	return ucred.Uid, ucred.Pid, nil
}
