//go:build windows

package jsonl

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

func TestIsLockContention(t *testing.T) {
	if !isLockContention(windows.ERROR_LOCK_VIOLATION) {
		t.Fatal("isLockContention(ERROR_LOCK_VIOLATION) = false, want true")
	}
	if !isLockContention(errors.Join(windows.ERROR_LOCK_VIOLATION)) {
		t.Fatal("isLockContention(wrapped ERROR_LOCK_VIOLATION) = false, want true")
	}
	if isLockContention(windows.ERROR_ACCESS_DENIED) {
		t.Fatal("isLockContention(ERROR_ACCESS_DENIED) = true, want false")
	}
}
