package session

import (
	"testing"
)

func TestCreateWithInvalidID(t *testing.T) {
	m := NewManager(2)
	if _, err := m.CreateWithID("bad id", "/tmp", ""); err != ErrInvalidSessionID {
		t.Fatalf("expected ErrInvalidSessionID, got %v", err)
	}
}

func TestDestroyReturnsFalseWhenMissing(t *testing.T) {
	m := NewManager(1)
	if ok := m.Destroy("none"); ok {
		t.Fatalf("expected false when destroying missing session")
	}
}

func TestCreateMaxSessionsLimit(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(1)
	if _, err := m.Create(dir, ""); err != nil {
		t.Fatalf("unexpected error creating first session: %v", err)
	}
	if _, err := m.Create(dir, ""); err == nil {
		t.Fatalf("expected error when exceeding maxSessions")
	}
}
