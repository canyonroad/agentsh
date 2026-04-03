//go:build darwin

package policysock

import "testing"

func TestSessionVersions_Lifecycle(t *testing.T) {
	sv := NewSessionVersions()

	// Register
	sv.Register("session-1")
	if v := sv.Get("session-1"); v != 1 {
		t.Fatalf("expected version 1, got %d", v)
	}

	// Increment
	sv.IncrementAll()
	if v := sv.Get("session-1"); v != 2 {
		t.Fatalf("expected version 2, got %d", v)
	}

	// Multiple sessions
	sv.Register("session-2")
	sv.IncrementAll()
	if v := sv.Get("session-1"); v != 3 {
		t.Fatalf("expected version 3, got %d", v)
	}
	if v := sv.Get("session-2"); v != 2 {
		t.Fatalf("expected version 2, got %d", v)
	}

	// Unregister
	sv.Unregister("session-1")
	if v := sv.Get("session-1"); v != 0 {
		t.Fatalf("expected 0 for unregistered session, got %d", v)
	}

	// Non-existent
	if v := sv.Get("nonexistent"); v != 0 {
		t.Fatalf("expected 0, got %d", v)
	}
}
