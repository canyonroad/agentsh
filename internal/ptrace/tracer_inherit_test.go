//go:build linux

package ptrace

import (
	"testing"
)

// TestFindParentByTGID covers the helper used by the minimal-state
// fallback callers to look up a parent by TGID.
func TestFindParentByTGID(t *testing.T) {
	tracees := map[int]*TraceeState{
		100: {TID: 100, TGID: 100, SessionID: "sess-A"},
		101: {TID: 101, TGID: 100, SessionID: "sess-A"}, // sibling thread shares TGID
		200: {TID: 200, TGID: 200, SessionID: "sess-B"},
	}

	if p := findParentByTGID(tracees, 100); p == nil || p.SessionID != "sess-A" {
		t.Fatalf("findParentByTGID(100) returned %+v", p)
	}
	if p := findParentByTGID(tracees, 200); p == nil || p.SessionID != "sess-B" {
		t.Fatalf("findParentByTGID(200) returned %+v", p)
	}
	if p := findParentByTGID(tracees, 999); p != nil {
		t.Fatalf("findParentByTGID(unknown) returned %+v, want nil", p)
	}
	for _, ppid := range []int{0, -1} {
		if p := findParentByTGID(tracees, ppid); p != nil {
			t.Fatalf("findParentByTGID(%d) returned %+v, want nil", ppid, p)
		}
	}
}

// TestSeedChildStateFromParent_CopiesAllEnforcementFields verifies the
// helper mirrors handleNewChild's create-from-scratch branch byte-for-
// byte (per PR #312 review). A child created via the minimal-state
// fallback path must end up indistinguishable from one created via the
// normal fork-event path in every enforcement-relevant field:
// SessionID, HasPrefilter, PendingPrefilter (skipped when parent
// already has filter), TGID-level escalation, thread-level escalation,
// and the SessionlessPIDAttach marker.
func TestSeedChildStateFromParent_CopiesAllEnforcementFields(t *testing.T) {
	parent := &TraceeState{
		TID:                      100,
		TGID:                     100,
		SessionID:                "sess-A",
		HasPrefilter:             true,
		PendingPrefilter:         true, // should be skipped: parent already has filter
		NeedsReadEscalation:      true,
		NeedsWriteEscalation:     true,
		ThreadHasReadEscalation:  true,
		ThreadHasWriteEscalation: true,
		SessionlessPIDAttach:     true,
	}

	child := seedChildStateFromParent(parent, 200, 200)
	if child == nil {
		t.Fatal("seedChildStateFromParent returned nil")
	}

	// Identity / bookkeeping
	if child.TID != 200 || child.TGID != 200 {
		t.Fatalf("child TID/TGID = %d/%d, want 200/200", child.TID, child.TGID)
	}
	if child.ParentPID != parent.TGID {
		t.Errorf("ParentPID = %d, want %d", child.ParentPID, parent.TGID)
	}
	if !child.SuppressInitialStop {
		t.Error("SuppressInitialStop must be true on a freshly-seeded child")
	}

	// Enforcement state copied
	if child.SessionID != parent.SessionID {
		t.Errorf("SessionID = %q, want %q", child.SessionID, parent.SessionID)
	}
	if !child.HasPrefilter {
		t.Error("HasPrefilter must be inherited (parent had it)")
	}
	// Parent already had the filter installed -> child inherits it via
	// fork, so PendingPrefilter must NOT be propagated.
	if child.PendingPrefilter {
		t.Error("PendingPrefilter must be false when parent already has filter installed")
	}
	if !child.NeedsReadEscalation || !child.NeedsWriteEscalation {
		t.Error("TGID-level escalation flags must be inherited")
	}
	if !child.ThreadHasReadEscalation || !child.ThreadHasWriteEscalation {
		t.Error("thread-level escalation flags must be inherited")
	}
	if !child.SessionlessPIDAttach {
		t.Error("SessionlessPIDAttach must be inherited so descendants of an attach_mode=pid root keep the marker")
	}

	// Per-thread runtime defaults
	if child.LastNr != -1 || child.MemFD != -1 ||
		child.PendingExecStubFD != -1 || child.PendingExecSavedFD != -1 {
		t.Errorf("runtime defaults wrong: LastNr=%d MemFD=%d PendingExecStubFD=%d PendingExecSavedFD=%d",
			child.LastNr, child.MemFD, child.PendingExecStubFD, child.PendingExecSavedFD)
	}
}

// TestSeedChildStateFromParent_PendingPrefilterPropagatedWhenParentLacksFilter
// verifies the conditional: when the parent does NOT have the prefilter
// installed yet (e.g. PendingPrefilter is true but HasPrefilter is
// false), the child must also be marked PendingPrefilter so the tracer
// installs it on the child's next syscall stop.
func TestSeedChildStateFromParent_PendingPrefilterPropagatedWhenParentLacksFilter(t *testing.T) {
	parent := &TraceeState{
		TID: 100, TGID: 100,
		SessionID: "sess-A", HasPrefilter: false, PendingPrefilter: true,
	}
	child := seedChildStateFromParent(parent, 200, 200)
	if child.HasPrefilter {
		t.Error("child HasPrefilter must mirror parent (false here)")
	}
	if !child.PendingPrefilter {
		t.Error("child PendingPrefilter must be true when parent has pending-but-not-installed filter")
	}
}

// TestSeedChildStateFromParent_NilParent verifies the helper returns a
// state with defaults only (no enforcement inheritance) when the parent
// is not known to the tracer. This path is hit on the very first
// fork-attach race before any tracee state exists.
func TestSeedChildStateFromParent_NilParent(t *testing.T) {
	child := seedChildStateFromParent(nil, 200, 200)
	if child == nil {
		t.Fatal("seedChildStateFromParent(nil, ...) returned nil")
	}
	if child.TID != 200 || child.TGID != 200 {
		t.Errorf("child TID/TGID = %d/%d, want 200/200", child.TID, child.TGID)
	}
	if child.SessionID != "" || child.HasPrefilter || child.PendingPrefilter ||
		child.NeedsReadEscalation || child.NeedsWriteEscalation ||
		child.ThreadHasReadEscalation || child.ThreadHasWriteEscalation ||
		child.SessionlessPIDAttach || child.ParentPID != 0 {
		t.Errorf("nil-parent child must have zero enforcement fields; got %+v", child)
	}
	if child.LastNr != -1 || child.MemFD != -1 {
		t.Error("nil-parent child must still have per-thread defaults")
	}
}
