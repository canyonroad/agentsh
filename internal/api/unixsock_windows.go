//go:build windows

package api

import "os"

// unixSocketPair represents a pair of connected Unix sockets.
// On Windows, this feature is not available.
type unixSocketPair struct {
	parent *os.File
	child  *os.File
}

// createUnixSocketPair returns nil on Windows as Unix sockets are not available.
// The Unix socket wrapper feature is disabled on Windows.
func createUnixSocketPair() *unixSocketPair {
	return nil
}
