package tor

import "testing"

func TestBuildControlEvent(t *testing.T) {
	ev := BuildControlEvent("sess-1", "cmd-1", 4242, Verdict{
		Vector: VectorProcess, Mode: ModeDeny, Decision: ModeDeny, Target: "/usr/bin/tor",
	})
	if ev.Type != "tor_control" {
		t.Fatalf("Type=%q, want tor_control", ev.Type)
	}
	if ev.SessionID != "sess-1" || ev.CommandID != "cmd-1" {
		t.Fatal("session/command not propagated")
	}
	if ev.Fields["vector"] != "process" || ev.Fields["decision"] != "deny" {
		t.Fatalf("fields wrong: %+v", ev.Fields)
	}
	if ev.PID != 4242 {
		t.Fatalf("PID=%d, want 4242", ev.PID)
	}
}
