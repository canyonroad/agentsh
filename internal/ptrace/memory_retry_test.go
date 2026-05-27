//go:build linux

package ptrace

import (
	"errors"
	"fmt"
	"testing"

	"golang.org/x/sys/unix"
)

func TestIsTransientMemErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"eio", unix.EIO, true},
		{"wrapped eio", fmt.Errorf("write BPF to tracee: %w", unix.EIO), true},
		{"efault", unix.EFAULT, false},
		{"eperm", unix.EPERM, false},
		{"nil", nil, false},
	}
	for _, c := range cases {
		if got := isTransientMemErr(c.err); got != c.want {
			t.Errorf("%s: isTransientMemErr(%v)=%v want %v", c.name, c.err, got, c.want)
		}
	}
}

func TestRetryTransientMem_RecoversAfterEIO(t *testing.T) {
	calls := 0
	err := retryTransientMem(0, 0x1000, "test", func() error {
		calls++
		if calls < 3 {
			return unix.EIO
		}
		return nil
	})
	if err != nil {
		t.Fatalf("expected success after retries, got %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 calls (2 EIO + 1 ok), got %d", calls)
	}
}

func TestRetryTransientMem_ExhaustsOnPersistentEIO(t *testing.T) {
	calls := 0
	err := retryTransientMem(0, 0x1000, "test", func() error {
		calls++
		return unix.EIO
	})
	if !errors.Is(err, unix.EIO) {
		t.Fatalf("expected EIO after exhaustion, got %v", err)
	}
	if calls != memRetryMaxAttempts {
		t.Fatalf("expected %d calls, got %d", memRetryMaxAttempts, calls)
	}
}

func TestRetryTransientMem_NonTransientReturnsImmediately(t *testing.T) {
	calls := 0
	err := retryTransientMem(0, 0x1000, "test", func() error {
		calls++
		return unix.EFAULT
	})
	if !errors.Is(err, unix.EFAULT) {
		t.Fatalf("expected EFAULT, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 call (no retry on non-transient), got %d", calls)
	}
}

func TestParseProcStatState(t *testing.T) {
	// comm (field 2) contains spaces and a paren; state char follows the LAST ')'.
	line := []byte("1234 (weird )name) t 1 1234 1234 0 -1 4194304 123 0 0 0")
	if got := parseProcStatState(line); got != "t" {
		t.Fatalf("parseProcStatState = %q, want \"t\"", got)
	}
	// Simple comm, running state.
	if got := parseProcStatState([]byte("42 (cat) R 1 42 42")); got != "R" {
		t.Fatalf("parseProcStatState(simple) = %q, want \"R\"", got)
	}
	// Malformed input → empty, never panics.
	if got := parseProcStatState([]byte("garbage with no paren")); got != "" {
		t.Fatalf("parseProcStatState(garbage) = %q, want \"\"", got)
	}
}
