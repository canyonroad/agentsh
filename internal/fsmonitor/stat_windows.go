//go:build windows

package fsmonitor

import "os"

// getNlink returns 1 on Windows as link count is not easily accessible.
// Windows NTFS supports hard links but the API to get link count is different.
func getNlink(info os.FileInfo) int {
	return 1
}
