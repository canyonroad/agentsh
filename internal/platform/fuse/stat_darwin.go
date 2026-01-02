// internal/platform/fuse/stat_darwin.go
//go:build darwin && cgo

package fuse

import (
	"syscall"
	"time"

	cgofuse "github.com/winfsp/cgofuse/fuse"
)

func fillStatTimes(stat *cgofuse.Stat_t, s *syscall.Stat_t) {
	stat.Atim = cgofuse.NewTimespec(time.Unix(s.Atimespec.Sec, s.Atimespec.Nsec))
	stat.Ctim = cgofuse.NewTimespec(time.Unix(s.Ctimespec.Sec, s.Ctimespec.Nsec))
}
