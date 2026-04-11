//go:build !linux && !windows

package api

import "os"

// unixSocketPair represents a pair of connected Unix sockets.
type unixSocketPair struct {
	parent *os.File
	child  *os.File
}

// createUnixSocketPair returns nil on non-Linux Unix platforms.
// Unix socket enforcement via seccomp user-notify is Linux-only.
func createUnixSocketPair() *unixSocketPair {
	return nil
}
