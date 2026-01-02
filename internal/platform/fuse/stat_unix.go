// internal/platform/fuse/stat_unix.go
//go:build (darwin || linux) && cgo

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

	if sys := info.Sys(); sys != nil {
		if s, ok := sys.(*syscall.Stat_t); ok {
			stat.Uid = s.Uid
			stat.Gid = s.Gid
			stat.Nlink = uint32(s.Nlink)
			stat.Ino = s.Ino
			stat.Dev = uint64(s.Dev)
			fillStatTimes(stat, s)
		}
	}
}

func timespecToTime(ts cgofuse.Timespec) time.Time {
	return time.Unix(ts.Sec, ts.Nsec)
}

// Chown changes file ownership (Unix only).
func (f *fuseFS) Chown(path string, uid uint32, gid uint32) int {
	realPath := f.realPath(path)
	if err := os.Chown(realPath, int(uid), int(gid)); err != nil {
		return toErrno(err)
	}
	return 0
}
