//go:build unix

package shim

import (
	"os"

	"golang.org/x/sys/unix"
)

// lockFileExclusive acquires an exclusive lock on the file.
func lockFileExclusive(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_EX)
}

// unlockFile releases the lock on the file.
func unlockFile(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_UN)
}

// defaultSessionBaseDirs returns platform-specific default directories for session files.
func defaultSessionBaseDirs(workspaceRoot string) []string {
	return []string{
		"/run/agentsh",
		"/tmp/agentsh",
		workspaceRoot + "/.agentsh",
	}
}
