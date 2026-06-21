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
	if ev.Fields["mode"] != "deny" || ev.Fields["target"] != "/usr/bin/tor" || ev.Fields["rule"] != "tor" {
		t.Fatalf("fields mode/target/rule wrong: %+v", ev.Fields)
	}
	if ev.PID != 4242 {
		t.Fatalf("PID=%d, want 4242", ev.PID)
	}
	if ev.ID == "" || ev.Timestamp.IsZero() {
		t.Fatalf("ID/Timestamp not populated: id=%q ts=%v", ev.ID, ev.Timestamp)
	}
}

func TestBuildGatewayEvent_Fields(t *testing.T) {
	ev := BuildGatewayEvent("session-1", "deny", "proxy_env_fallback", false)
	if ev.Type != "tor_control" {
		t.Fatalf("type = %q, want tor_control", ev.Type)
	}
	if ev.Fields["vector"] != VectorGateway {
		t.Fatalf("vector = %v, want %q", ev.Fields["vector"], VectorGateway)
	}
	if ev.Fields["decision"] != "deny" || ev.Fields["reason"] != "proxy_env_fallback" {
		t.Fatalf("unexpected fields: %v", ev.Fields)
	}
	if ev.Fields["enforced"] != false {
		t.Fatalf("enforced = %v, want false", ev.Fields["enforced"])
	}
}
