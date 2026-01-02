// internal/platform/fuse/stat_linux.go
//go:build linux && cgo

package fuse

import (
	"syscall"
	"time"

	cgofuse "github.com/winfsp/cgofuse/fuse"
)

func fillStatTimes(stat *cgofuse.Stat_t, s *syscall.Stat_t) {
	stat.Atim = cgofuse.NewTimespec(time.Unix(s.Atim.Sec, s.Atim.Nsec))
	stat.Ctim = cgofuse.NewTimespec(time.Unix(s.Ctim.Sec, s.Ctim.Nsec))
}
