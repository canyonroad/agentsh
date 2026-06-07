//go:build linux

package ptrace

import (
	"testing"
)

// TestBindSession_UpdatesSessionlessTracee verifies that BindSession promotes
// a SessionlessPIDAttach tracee to a real session — the primary fix for #416
// (opaque enforce bypassed in attach_mode=pid + shim). Without BindSession the
// only path was AttachPID → PtraceSeize, which fails EPERM for auto-inherited
// descendants, leaving them sessionless and HandleExecve passes them through.
func TestBindSession_UpdatesSessionlessTracee(t *testing.T) {
	tr := &Tracer{tracees: make(map[int]*TraceeState)}

	// Simulate a child auto-inherited via PTRACE_O_TRACEFORK with no session.
	pid := 1001
	tr.tracees[pid] = &TraceeState{
		TID:                  pid,
		TGID:                 pid,
		SessionlessPIDAttach: true,
		SessionID:            "",
	}

	if err := tr.BindSession(pid, "sess-abc"); err != nil {
		t.Fatalf("BindSession: %v", err)
	}

	st := tr.tracees[pid]
	if st.SessionID != "sess-abc" {
		t.Errorf("SessionID = %q, want %q", st.SessionID, "sess-abc")
	}
	if st.SessionlessPIDAttach {
		t.Error("SessionlessPIDAttach should be false after BindSession")
	}
}

// TestBindSession_UpdatesAllThreadsForTGID verifies that BindSession updates
// every thread whose TGID matches — not just the main thread.
func TestBindSession_UpdatesAllThreadsForTGID(t *testing.T) {
	tr := &Tracer{tracees: make(map[int]*TraceeState)}

	// Main thread and two worker threads sharing TGID 2000.
	for _, tid := range []int{2000, 2001, 2002} {
		tr.tracees[tid] = &TraceeState{
			TID:                  tid,
			TGID:                 2000,
			SessionlessPIDAttach: true,
		}
	}

	if err := tr.BindSession(2000, "sess-multi"); err != nil {
		t.Fatalf("BindSession: %v", err)
	}

	for _, tid := range []int{2000, 2001, 2002} {
		st := tr.tracees[tid]
		if st.SessionID != "sess-multi" {
			t.Errorf("tid %d: SessionID = %q, want %q", tid, st.SessionID, "sess-multi")
		}
		if st.SessionlessPIDAttach {
			t.Errorf("tid %d: SessionlessPIDAttach should be false", tid)
		}
	}
}

// TestBindSession_ErrorOnUnknownPID verifies BindSession returns an error
// when the PID is not in the tracees map (not yet traced or already exited).
func TestBindSession_ErrorOnUnknownPID(t *testing.T) {
	tr := &Tracer{tracees: make(map[int]*TraceeState)}

	if err := tr.BindSession(9999, "sess-x"); err == nil {
		t.Error("expected error for unknown PID, got nil")
	}
}

// TestBindSession_UnrelatedThreadsUntouched verifies that BindSession for TGID A
// does not modify tracees belonging to an unrelated TGID B.
func TestBindSession_UnrelatedThreadsUntouched(t *testing.T) {
	tr := &Tracer{tracees: make(map[int]*TraceeState)}

	tr.tracees[3000] = &TraceeState{TID: 3000, TGID: 3000, SessionlessPIDAttach: true}
	tr.tracees[4000] = &TraceeState{TID: 4000, TGID: 4000, SessionlessPIDAttach: true}

	if err := tr.BindSession(3000, "sess-3k"); err != nil {
		t.Fatalf("BindSession: %v", err)
	}

	if tr.tracees[4000].SessionID != "" || !tr.tracees[4000].SessionlessPIDAttach {
		t.Error("unrelated TGID 4000 was modified by BindSession for TGID 3000")
	}
}
