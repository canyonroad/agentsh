//go:build windows

package shim

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// lockFileExclusive acquires an exclusive lock on the file.
// On Windows, we use LockFileEx with LOCKFILE_EXCLUSIVE_LOCK.
func lockFileExclusive(f *os.File) error {
	var overlapped windows.Overlapped
	return windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK,
		0,
		1, 0,
		&overlapped,
	)
}

// unlockFile releases the lock on the file.
func unlockFile(f *os.File) error {
	var overlapped windows.Overlapped
	return windows.UnlockFileEx(
		windows.Handle(f.Fd()),
		0,
		1, 0,
		&overlapped,
	)
}

// defaultSessionBaseDirs returns platform-specific default directories for session files.
func defaultSessionBaseDirs(workspaceRoot string) []string {
	// On Windows, use %LOCALAPPDATA%\agentsh or fallback to workspace
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		home, _ := os.UserHomeDir()
		localAppData = filepath.Join(home, "AppData", "Local")
	}

	tempDir := os.Getenv("TEMP")
	if tempDir == "" {
		tempDir = os.TempDir()
	}

	return []string{
		filepath.Join(localAppData, "agentsh"),
		filepath.Join(tempDir, "agentsh"),
		filepath.Join(workspaceRoot, ".agentsh"),
	}
}
