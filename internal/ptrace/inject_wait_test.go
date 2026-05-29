//go:build linux

package ptrace

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// TestWaitForSyscallStopUntil_RespectsDeadline verifies the inject wait is bounded
// by its deadline and returns promptly rather than spinning — the core of the
// #369 #2 inject-spin fix (the previous 5s-per-call clock could compound to tens
// of seconds per exec). With an already-past deadline it must return a timeout
// error on the first iteration, before any Wait4.
func TestWaitForSyscallStopUntil_RespectsDeadline(t *testing.T) {
	tr := NewTracer(TracerConfig{})
	start := time.Now()
	err := tr.waitForSyscallStopUntil(1<<30, time.Now().Add(-time.Second))
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected a timeout error for a past deadline, got %v", err)
	}
	if d := time.Since(start); d > 250*time.Millisecond {
		t.Errorf("waitForSyscallStopUntil must return promptly on a past deadline; took %v", d)
	}
}

// TestErrInjectTraceeVanished_Distinct guards the sentinel used to abort an
// inject when the tracee disappeared from /proc mid-injection (#369 #2), so the
// caller can tell it apart from other inject errors if it ever needs to.
func TestErrInjectTraceeVanished_Distinct(t *testing.T) {
	if errInjectTraceeVanished == nil {
		t.Fatal("errInjectTraceeVanished must be defined")
	}
	if !errors.Is(errInjectTraceeVanished, errInjectTraceeVanished) {
		t.Error("errInjectTraceeVanished must match itself via errors.Is")
	}
	if errors.Is(errInjectTraceeVanished, errScratchUnmapped) {
		t.Error("errInjectTraceeVanished must be distinct from errScratchUnmapped")
	}
}
