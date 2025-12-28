//go:build !windows

package api

import (
	"os"

	"golang.org/x/sys/unix"
)

// unixSocketPair represents a pair of connected Unix sockets.
type unixSocketPair struct {
	parent *os.File
	child  *os.File
}

// createUnixSocketPair creates a Unix socket pair for IPC.
// Returns nil if socket pair creation fails.
func createUnixSocketPair() *unixSocketPair {
	sp, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		return nil
	}
	return &unixSocketPair{
		parent: os.NewFile(uintptr(sp[0]), "notify-parent"),
		child:  os.NewFile(uintptr(sp[1]), "notify-child"),
	}
}
