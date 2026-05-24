package session

import "testing"

// Issue #377 (part 2): the FUSE symlink-escape check needs a lightweight cwd
// accessor (no env/history copy) and a once-per-session diagnostic latch.

func TestGetCwd_ReturnsCurrentCwd(t *testing.T) {
	s := &Session{Cwd: "/workspace/proj"}
	if got := s.GetCwd(); got != "/workspace/proj" {
		t.Errorf("GetCwd() = %q, want %q", got, "/workspace/proj")
	}
}

func TestFirstCwdEscapeWarn_TrueExactlyOnce(t *testing.T) {
	s := &Session{}
	if !s.FirstCwdEscapeWarn() {
		t.Fatal("first FirstCwdEscapeWarn() = false, want true")
	}
	for i := 0; i < 3; i++ {
		if s.FirstCwdEscapeWarn() {
			t.Fatalf("FirstCwdEscapeWarn() returned true on subsequent call %d, want false", i+2)
		}
	}
}
