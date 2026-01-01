// internal/platform/darwin/xpc/sessions_test.go
package xpc

import (
	"testing"
)

func TestSessionTracker_RegisterAndLookup(t *testing.T) {
	tracker := NewSessionTracker()

	tracker.RegisterProcess("session-1", 100, 0)   // root process
	tracker.RegisterProcess("session-1", 101, 100) // child

	if sid := tracker.SessionForPID(100); sid != "session-1" {
		t.Errorf("pid 100: got %q, want %q", sid, "session-1")
	}
	if sid := tracker.SessionForPID(101); sid != "session-1" {
		t.Errorf("pid 101: got %q, want %q", sid, "session-1")
	}
	if sid := tracker.SessionForPID(999); sid != "" {
		t.Errorf("pid 999: got %q, want empty", sid)
	}
}

func TestSessionTracker_ParentWalk(t *testing.T) {
	tracker := NewSessionTracker()

	// Register root process
	tracker.RegisterProcess("session-1", 100, 0)

	// Simulate fork chain: 100 -> 101 -> 102 -> 103
	tracker.SetParent(101, 100)
	tracker.SetParent(102, 101)
	tracker.SetParent(103, 102)

	// Should find session via parent walk
	if sid := tracker.SessionForPID(103); sid != "session-1" {
		t.Errorf("pid 103: got %q, want %q", sid, "session-1")
	}

	// Verify caching - 103 should now be cached
	if sid := tracker.SessionForPID(103); sid != "session-1" {
		t.Errorf("pid 103 cached: got %q, want %q", sid, "session-1")
	}
}

func TestSessionTracker_ProcessExit(t *testing.T) {
	tracker := NewSessionTracker()

	tracker.RegisterProcess("session-1", 100, 0)
	tracker.RegisterProcess("session-1", 101, 100)

	tracker.UnregisterProcess(101)

	if sid := tracker.SessionForPID(101); sid != "" {
		t.Errorf("pid 101 after exit: got %q, want empty", sid)
	}
	// Root process should still be tracked
	if sid := tracker.SessionForPID(100); sid != "session-1" {
		t.Errorf("pid 100: got %q, want %q", sid, "session-1")
	}
}

func TestSessionTracker_SessionEnd(t *testing.T) {
	tracker := NewSessionTracker()

	tracker.RegisterProcess("session-1", 100, 0)
	tracker.RegisterProcess("session-1", 101, 100)

	tracker.EndSession("session-1")

	if sid := tracker.SessionForPID(100); sid != "" {
		t.Errorf("pid 100 after session end: got %q, want empty", sid)
	}
	if sid := tracker.SessionForPID(101); sid != "" {
		t.Errorf("pid 101 after session end: got %q, want empty", sid)
	}
}

func TestSessionTracker_CircularParentRef(t *testing.T) {
	tracker := NewSessionTracker()

	// Register a session with root process
	tracker.RegisterProcess("session-1", 100, 0)

	// Create a circular parent reference: 101 -> 102 -> 101
	tracker.SetParent(101, 102)
	tracker.SetParent(102, 101)

	// Should not hang, should return empty (no session found through cycle)
	if sid := tracker.SessionForPID(101); sid != "" {
		t.Errorf("circular ref from 101: got %q, want empty", sid)
	}
	if sid := tracker.SessionForPID(102); sid != "" {
		t.Errorf("circular ref from 102: got %q, want empty", sid)
	}
}

func TestSessionTracker_ParentWalkDepthLimit(t *testing.T) {
	tracker := NewSessionTracker()

	// Register session with root process at pid 1
	tracker.RegisterProcess("session-1", 1, 0)

	// Create a chain longer than maxParentWalkDepth (10):
	// 1 <- 2 <- 3 <- 4 <- 5 <- 6 <- 7 <- 8 <- 9 <- 10 <- 11 <- 12
	// So pid 12 is 11 levels away from pid 1
	for i := int32(2); i <= 12; i++ {
		tracker.SetParent(i, i-1)
	}

	// Test depth limit FIRST before any caching happens
	// pid 12 should NOT find session (would need 11 hops, exceeds max of 10)
	if sid := tracker.SessionForPID(12); sid != "" {
		t.Errorf("pid 12 (11 hops, exceeds limit): got %q, want empty", sid)
	}

	// pid 11 should find session (10 hops: 11->10->9->8->7->6->5->4->3->2->1)
	if sid := tracker.SessionForPID(11); sid != "session-1" {
		t.Errorf("pid 11 (10 hops): got %q, want %q", sid, "session-1")
	}

	// Now pid 12 should find session through cached pid 11 (1 hop)
	if sid := tracker.SessionForPID(12); sid != "session-1" {
		t.Errorf("pid 12 after caching: got %q, want %q", sid, "session-1")
	}
}
