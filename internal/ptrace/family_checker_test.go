//go:build linux

package ptrace

import (
	"context"
	"sync"
	"testing"

	"github.com/agentsh/agentsh/internal/seccomp"
	"github.com/agentsh/agentsh/pkg/types"
	"golang.org/x/sys/unix"
)

func TestFamilyChecker_Check_MatchAndMiss(t *testing.T) {
	c := NewFamilyChecker([]seccomp.BlockedFamily{
		{Family: 38, Action: seccomp.OnBlockErrno, Name: "AF_ALG"},
	})

	// AF_ALG on socket(2) → match.
	bf, ok := c.Check(uint64(unix.SYS_SOCKET), 38)
	if !ok || bf.Name != "AF_ALG" {
		t.Errorf("expected match for AF_ALG on SYS_SOCKET; got bf=%+v ok=%v", bf, ok)
	}

	// AF_INET on socket(2) → miss.
	if _, ok := c.Check(uint64(unix.SYS_SOCKET), 2); ok {
		t.Errorf("expected miss for AF_INET")
	}

	// AF_ALG on read(2) → miss (only socket/socketpair are checked).
	if _, ok := c.Check(uint64(unix.SYS_READ), 38); ok {
		t.Errorf("expected miss for AF_ALG on SYS_READ")
	}
}

func TestFamilyChecker_Check_Socketpair(t *testing.T) {
	c := NewFamilyChecker([]seccomp.BlockedFamily{
		{Family: 38, Action: seccomp.OnBlockErrno, Name: "AF_ALG"},
	})
	_, ok := c.Check(uint64(unix.SYS_SOCKETPAIR), 38)
	if !ok {
		t.Errorf("expected match for AF_ALG on SYS_SOCKETPAIR")
	}
}

func TestFamilyChecker_Empty(t *testing.T) {
	c := NewFamilyChecker(nil)
	if _, ok := c.Check(uint64(unix.SYS_SOCKET), 38); ok {
		t.Errorf("empty checker should never match")
	}
}

func TestFamilyChecker_MultipleEntries(t *testing.T) {
	c := NewFamilyChecker([]seccomp.BlockedFamily{
		{Family: 38, Action: seccomp.OnBlockErrno, Name: "AF_ALG"},
		{Family: 40, Action: seccomp.OnBlockKill, Name: "AF_VSOCK"},
		{Family: 21, Action: seccomp.OnBlockLog, Name: "AF_RDS"},
	})

	cases := []struct {
		syscall uint64
		family  uint64
		want    bool
		name    string
		action  seccomp.OnBlockAction
	}{
		{uint64(unix.SYS_SOCKET), 38, true, "AF_ALG", seccomp.OnBlockErrno},
		{uint64(unix.SYS_SOCKET), 40, true, "AF_VSOCK", seccomp.OnBlockKill},
		{uint64(unix.SYS_SOCKETPAIR), 21, true, "AF_RDS", seccomp.OnBlockLog},
		{uint64(unix.SYS_SOCKET), 2, false, "", ""},
		{uint64(unix.SYS_SOCKET), 10, false, "", ""},
	}

	for _, tc := range cases {
		bf, ok := c.Check(tc.syscall, tc.family)
		if ok != tc.want {
			t.Errorf("Check(%d, %d): ok=%v want=%v", tc.syscall, tc.family, ok, tc.want)
			continue
		}
		if ok {
			if bf.Name != tc.name {
				t.Errorf("Check(%d, %d): name=%q want=%q", tc.syscall, tc.family, bf.Name, tc.name)
			}
			if bf.Action != tc.action {
				t.Errorf("Check(%d, %d): action=%v want=%v", tc.syscall, tc.family, bf.Action, tc.action)
			}
		}
	}
}

func TestFamilyChecker_NilReceiver(t *testing.T) {
	var c *FamilyChecker
	if _, ok := c.Check(uint64(unix.SYS_SOCKET), 38); ok {
		t.Errorf("nil receiver should never match")
	}
}

// applyTestEmitter is a thread-safe in-memory sink for Apply unit tests.
type applyTestEmitter struct {
	mu     sync.Mutex
	events []types.Event
}

func (e *applyTestEmitter) AppendEvent(_ context.Context, ev types.Event) error {
	e.mu.Lock()
	e.events = append(e.events, ev)
	e.mu.Unlock()
	return nil
}

func (e *applyTestEmitter) Publish(ev types.Event) {
	e.mu.Lock()
	e.events = append(e.events, ev)
	e.mu.Unlock()
}

func (e *applyTestEmitter) Events() []types.Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]types.Event, len(e.events))
	copy(out, e.events)
	return out
}

// makeApplyChecker builds a FamilyChecker with the given emitter and injects
// the provided tgkill and denySyscall seams. A nil seam means the field is
// not overridden (production behaviour would apply, but tests always set both).
func makeApplyChecker(
	emit FamilyEmitter,
	tgkill func(tgid, tid int, sig unix.Signal) error,
	denySyscall func(tid int, errno int) error,
) *FamilyChecker {
	c := NewFamilyCheckerWithEmitter([]seccomp.BlockedFamily{
		{Family: unix.AF_ALG, Action: seccomp.OnBlockLogAndKill, Name: "AF_ALG"},
	}, emit)
	if tgkill != nil {
		c.tgkillFn = tgkill
	}
	if denySyscall != nil {
		c.denySyscallFn = denySyscall
	}
	return c
}

// bf is a helper BlockedFamily value for the Apply unit tests.
var applyBF = seccomp.BlockedFamily{
	Family: unix.AF_ALG,
	Name:   "AF_ALG",
	Action: seccomp.OnBlockLogAndKill,
}

// TestApply_LogAndKill_TgkillFailure_NonESRCH verifies that when Tgkill
// returns a non-ESRCH error and denySyscall succeeds, the emitted outcome is
// "denied" — NOT "killed". This is the core correctness fix for Bug 1.
func TestApply_LogAndKill_TgkillFailure_NonESRCH(t *testing.T) {
	sink := &applyTestEmitter{}
	c := makeApplyChecker(
		sink,
		func(tgid, tid int, sig unix.Signal) error { return unix.EPERM },
		func(tid int, errno int) error { return nil }, // deny succeeds
	)

	err := c.Apply(100, 200, nil, seccomp.OnBlockLogAndKill, unix.SYS_SOCKET, applyBF, "sess-1")
	if err != ptraceAlreadyResumed {
		t.Errorf("Apply return = %v; want ptraceAlreadyResumed", err)
	}

	evts := sink.Events()
	if len(evts) == 0 {
		t.Fatal("expected at least one audit event; got none")
	}
	outcome, _ := evts[0].Fields["outcome"].(string)
	if outcome == "killed" {
		t.Errorf("outcome=%q; must NOT be \"killed\" when Tgkill failed — want \"denied\"", outcome)
	}
	if outcome != "denied" {
		t.Errorf("outcome=%q; want \"denied\" (deny-fallback succeeded)", outcome)
	}
}

// TestApply_LogAndKill_TgkillFailure_DenyAlsoFails verifies that when both
// Tgkill and denySyscall fail, the emitted outcome is "deny_fallback_failed".
func TestApply_LogAndKill_TgkillFailure_DenyAlsoFails(t *testing.T) {
	sink := &applyTestEmitter{}
	c := makeApplyChecker(
		sink,
		func(tgid, tid int, sig unix.Signal) error { return unix.EPERM },
		func(tid int, errno int) error { return unix.EIO },
	)

	err := c.Apply(100, 200, nil, seccomp.OnBlockLogAndKill, unix.SYS_SOCKET, applyBF, "sess-2")
	if err != ptraceAlreadyResumed {
		t.Errorf("Apply return = %v; want ptraceAlreadyResumed", err)
	}

	evts := sink.Events()
	if len(evts) == 0 {
		t.Fatal("expected at least one audit event; got none")
	}
	outcome, _ := evts[0].Fields["outcome"].(string)
	if outcome == "killed" {
		t.Errorf("outcome=%q; must NOT be \"killed\" when Tgkill failed", outcome)
	}
	if outcome != "deny_fallback_failed" {
		t.Errorf("outcome=%q; want \"deny_fallback_failed\"", outcome)
	}
}

// TestApply_LogAndKill_TgkillSuccess verifies that when Tgkill succeeds, the
// emitted outcome is "killed" and Apply returns PtraceKillRequested.
func TestApply_LogAndKill_TgkillSuccess(t *testing.T) {
	sink := &applyTestEmitter{}
	c := makeApplyChecker(
		sink,
		func(tgid, tid int, sig unix.Signal) error { return nil },
		func(tid int, errno int) error {
			t.Fatal("denySyscall must not be called on Tgkill success")
			return nil
		},
	)

	err := c.Apply(100, 200, nil, seccomp.OnBlockLogAndKill, unix.SYS_SOCKET, applyBF, "sess-3")
	if err != PtraceKillRequested {
		t.Errorf("Apply return = %v; want PtraceKillRequested", err)
	}

	evts := sink.Events()
	if len(evts) == 0 {
		t.Fatal("expected at least one audit event; got none")
	}
	outcome, _ := evts[0].Fields["outcome"].(string)
	if outcome != "killed" {
		t.Errorf("outcome=%q; want \"killed\"", outcome)
	}
}

// TestApply_LogAndKill_TgkillESRCH verifies that when Tgkill returns ESRCH
// (target already gone), the emitted outcome is "vanished" and Apply returns nil.
func TestApply_LogAndKill_TgkillESRCH(t *testing.T) {
	sink := &applyTestEmitter{}
	c := makeApplyChecker(
		sink,
		func(tgid, tid int, sig unix.Signal) error { return unix.ESRCH },
		func(tid int, errno int) error { t.Fatal("denySyscall must not be called on ESRCH"); return nil },
	)

	err := c.Apply(100, 200, nil, seccomp.OnBlockLogAndKill, unix.SYS_SOCKET, applyBF, "sess-4")
	if err != nil {
		t.Errorf("Apply return = %v; want nil (target already gone)", err)
	}

	// ESRCH (vanished): no event should be emitted as the target is gone.
	// The outcome field would be "vanished" but the event is emitted.
	evts := sink.Events()
	if len(evts) == 0 {
		t.Fatal("expected at least one audit event for vanished target; got none")
	}
	outcome, _ := evts[0].Fields["outcome"].(string)
	if outcome != "vanished" {
		t.Errorf("outcome=%q; want \"vanished\"", outcome)
	}
}

// TestApply_Log_DenySyscallFailure verifies that when denySyscall fails with a
// non-ESRCH error in OnBlockLog mode, the emitted outcome is "deny_failed".
func TestApply_Log_DenySyscallFailure(t *testing.T) {
	logBF := seccomp.BlockedFamily{
		Family: unix.AF_ALG,
		Name:   "AF_ALG",
		Action: seccomp.OnBlockLog,
	}
	sink := &applyTestEmitter{}
	c := NewFamilyCheckerWithEmitter([]seccomp.BlockedFamily{logBF}, sink)
	c.denySyscallFn = func(tid int, errno int) error { return unix.EIO }

	err := c.Apply(100, 200, nil, seccomp.OnBlockLog, unix.SYS_SOCKET, logBF, "sess-5")
	// EIO from denySyscall is returned directly.
	if err != unix.EIO {
		t.Errorf("Apply return = %v; want EIO", err)
	}

	evts := sink.Events()
	if len(evts) == 0 {
		t.Fatal("expected at least one audit event; got none")
	}
	outcome, _ := evts[0].Fields["outcome"].(string)
	if outcome == "denied" {
		t.Errorf("outcome=%q; must NOT be \"denied\" when denySyscall failed — want \"deny_failed\"", outcome)
	}
	if outcome != "deny_failed" {
		t.Errorf("outcome=%q; want \"deny_failed\"", outcome)
	}
}
