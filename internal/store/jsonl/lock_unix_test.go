//go:build unix

package jsonl

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

func TestIsLockContention(t *testing.T) {
	t.Parallel()

	if !isLockContention(unix.EWOULDBLOCK) {
		t.Fatal("isLockContention(EWOULDBLOCK) = false, want true")
	}
	if !isLockContention(fmtError(unix.EAGAIN)) {
		t.Fatal("isLockContention(wrapped EAGAIN) = false, want true")
	}
	if isLockContention(unix.EIO) {
		t.Fatal("isLockContention(EIO) = true, want false")
	}
}

func fmtError(err error) error {
	return errors.Join(err)
}
