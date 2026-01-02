//go:build !windows

package fsmonitor

import (
	"os"
	"syscall"
)

// getNlink extracts the link count from file info on Unix systems.
func getNlink(info os.FileInfo) int {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(stat.Nlink)
	}
	return 0
}
