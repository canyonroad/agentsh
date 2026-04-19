//go:build windows

package wal

import "golang.org/x/sys/windows"

// syncDir is a no-op on Windows: NTFS does not provide a directory-fsync
// primitive equivalent to Linux's fsync(dirfd). Durability of the rename is
// instead delivered by MOVEFILE_WRITE_THROUGH inside atomicRename.
func syncDir(string) error { return nil }

// atomicRename renames from→to via MoveFileEx with MOVEFILE_REPLACE_EXISTING
// |MOVEFILE_WRITE_THROUGH so the directory entry is durable on return,
// matching the unix os.Rename + syncDir(parent) guarantee.
func atomicRename(from, to string) error {
	fromPtr, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	toPtr, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(fromPtr, toPtr, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
