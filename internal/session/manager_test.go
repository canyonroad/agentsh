package session

import (
	"testing"
	"time"
)

func TestManager_ReapExpired_IdleTimeout(t *testing.T) {
	m := NewManager(10)
	ws := t.TempDir()

	s, err := m.Create(ws, "default")
	if err != nil {
		t.Fatal(err)
	}
	base := s.CreatedAt

	// Should not reap before idle timeout.
	if got := m.ReapExpired(base.Add(29*time.Minute), 0, 30*time.Minute); len(got) != 0 {
		t.Fatalf("expected no reaped sessions, got %d", len(got))
	}
	if _, ok := m.Get(s.ID); !ok {
		t.Fatalf("expected session still present")
	}

	// Should reap after idle timeout.
	got := m.ReapExpired(base.Add(31*time.Minute), 0, 30*time.Minute)
	if len(got) != 1 || got[0].ID != s.ID {
		t.Fatalf("expected to reap session %s, got %+v", s.ID, got)
	}
	if _, ok := m.Get(s.ID); ok {
		t.Fatalf("expected session removed")
	}
}

func TestManager_ReapExpired_TouchExtendsIdle(t *testing.T) {
	m := NewManager(10)
	ws := t.TempDir()

	s, err := m.Create(ws, "default")
	if err != nil {
		t.Fatal(err)
	}
	base := s.CreatedAt

	// Activity at +20m should prevent reaping at +31m with 30m idle timeout.
	s.TouchAt(base.Add(20 * time.Minute))
	if got := m.ReapExpired(base.Add(31*time.Minute), 0, 30*time.Minute); len(got) != 0 {
		t.Fatalf("expected no reaped sessions, got %d", len(got))
	}
	if _, ok := m.Get(s.ID); !ok {
		t.Fatalf("expected session still present")
	}
}

func TestManager_ReapExpired_SessionTimeoutWins(t *testing.T) {
	m := NewManager(10)
	ws := t.TempDir()

	s, err := m.Create(ws, "default")
	if err != nil {
		t.Fatal(err)
	}
	base := s.CreatedAt

	// Even with recent activity, session timeout should reap.
	s.TouchAt(base.Add(59 * time.Minute))
	got := m.ReapExpired(base.Add(61*time.Minute), 1*time.Hour, 2*time.Hour)
	if len(got) != 1 || got[0].ID != s.ID {
		t.Fatalf("expected to reap session by session_timeout, got %+v", got)
	}
}

func TestCreateWithProfile(t *testing.T) {
	m := NewManager(10)

	mounts := []ResolvedMount{
		{Path: "/workspace", Policy: "workspace-rw"},
		{Path: "/config", Policy: "config-readonly"},
	}

	s, err := m.CreateWithProfile("test_id", "my-profile", "default", mounts)
	if err != nil {
		t.Fatalf("CreateWithProfile: %v", err)
	}

	if s.Profile != "my-profile" {
		t.Errorf("Profile = %q, want %q", s.Profile, "my-profile")
	}
	if len(s.Mounts) != 2 {
		t.Errorf("len(Mounts) = %d, want 2", len(s.Mounts))
	}
	if s.Policy != "default" {
		t.Errorf("Policy = %q, want %q", s.Policy, "default")
	}
	// First mount path should be used as workspace
	if s.Workspace != "/workspace" {
		t.Errorf("Workspace = %q, want %q", s.Workspace, "/workspace")
	}
}
