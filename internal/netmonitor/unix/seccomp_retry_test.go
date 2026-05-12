//go:build linux && cgo

package unix

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

// TestLoadFilterWithRetry_RetriesOnEINVAL is the regression check for
// the WAIT_KILLABLE-rejection fallback used by custom/vendor kernels
// that report kernel >=5.19 but return EINVAL when given the flag.
// (Equivalent unit-level coverage also lives in seccomp_load_linux_test.go;
// this file is the long-term home of retry-semantic regression checks.)
func TestLoadFilterWithRetry_RetriesOnEINVAL(t *testing.T) {
	var attempts []uintptr
	withStubbedSeams(t, func(flags uintptr, _ *unix.SockFprog) (int, error) {
		attempts = append(attempts, flags)
		if len(attempts) == 1 {
			return -1, unix.EINVAL
		}
		return 7, nil
	})
	fd, gotWaitKill, err := loadFilterWithRetry(minimalBPF(), true, nil)
	if err != nil {
		t.Fatalf("loadFilterWithRetry: %v", err)
	}
	if fd != 7 {
		t.Fatalf("fd = %d, want 7", fd)
	}
	if gotWaitKill {
		t.Fatalf("expected gotWaitKill=false after retry, got true")
	}
	if len(attempts) != 2 {
		t.Fatalf("expected 2 attempts, got %d", len(attempts))
	}
}

// TestLoadFilterWithRetry_PropagatesOriginalErrno is the regression
// check for issue #282 — non-EINVAL errnos must surface verbatim so
// hostile-kernel rejections (EFAULT on Runloop/Freestyle) land in the
// wrapper's stderr with their real cause, not a misleading
// "WaitKillable rejected" warning.
func TestLoadFilterWithRetry_PropagatesOriginalErrno(t *testing.T) {
	withStubbedSeams(t, func(uintptr, *unix.SockFprog) (int, error) {
		return -1, unix.EFAULT
	})
	_, _, err := loadFilterWithRetry(minimalBPF(), true, nil)
	if !errors.Is(err, unix.EFAULT) {
		t.Fatalf("expected EFAULT to propagate, got %v", err)
	}
}
