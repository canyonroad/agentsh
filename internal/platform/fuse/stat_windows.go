// internal/platform/fuse/stat_windows.go
//go:build windows && cgo

package fuse

import (
	"os"
	"syscall"
	"time"

	cgofuse "github.com/winfsp/cgofuse/fuse"
)

func fillStat(stat *cgofuse.Stat_t, info os.FileInfo) {
	stat.Size = info.Size()
	stat.Mtim = cgofuse.NewTimespec(info.ModTime())
	stat.Atim = stat.Mtim
	stat.Ctim = stat.Mtim

	mode := uint32(info.Mode().Perm())
	if info.IsDir() {
		mode |= cgofuse.S_IFDIR
	} else if info.Mode()&os.ModeSymlink != 0 {
		mode |= cgofuse.S_IFLNK
	} else {
		mode |= cgofuse.S_IFREG
	}
	stat.Mode = mode
	stat.Nlink = 1

	// Windows: extract times from Win32FileAttributeData
	if sys := info.Sys(); sys != nil {
		if s, ok := sys.(*syscall.Win32FileAttributeData); ok {
			stat.Atim = cgofuse.NewTimespec(filetimeToTime(s.LastAccessTime))
			stat.Ctim = cgofuse.NewTimespec(filetimeToTime(s.CreationTime))
		}
	}
	// Windows: UID/GID not meaningful, leave as 0
}

func filetimeToTime(ft syscall.Filetime) time.Time {
	return time.Unix(0, ft.Nanoseconds())
}

func timespecToTime(ts cgofuse.Timespec) time.Time {
	return time.Unix(ts.Sec, ts.Nsec)
}

// Chown is a no-op on Windows (ACLs managed separately).
func (f *fuseFS) Chown(path string, uid uint32, gid uint32) int {
	return 0
}
