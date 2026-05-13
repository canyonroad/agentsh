package api

import (
	"testing"
	"time"

	dbevents "github.com/agentsh/agentsh/internal/db/events"
)

func TestDBLifecycleToEventUsesClientIdentityWhenSessionIDEmpty(t *testing.T) {
	ev := dbLifecycleToEvent(dbevents.LifecycleEvent{
		EventID:        "evt-1",
		Timestamp:      time.Unix(123, 0).UTC(),
		Kind:           "db_handshake_fail",
		ClientIdentity: "sess-client",
	})

	if ev.SessionID != "sess-client" {
		t.Fatalf("SessionID = %q, want ClientIdentity fallback", ev.SessionID)
	}
}

func TestDBLifecycleToEventPreservesExplicitSessionID(t *testing.T) {
	ev := dbLifecycleToEvent(dbevents.LifecycleEvent{
		EventID:        "evt-1",
		Timestamp:      time.Unix(123, 0).UTC(),
		Kind:           "db_handshake_fail",
		SessionID:      "sess-explicit",
		ClientIdentity: "sess-client",
	})

	if ev.SessionID != "sess-explicit" {
		t.Fatalf("SessionID = %q, want explicit SessionID", ev.SessionID)
	}
}

func TestDBLifecycleToEventDoesNotUseUIDClientIdentityAsSessionID(t *testing.T) {
	ev := dbLifecycleToEvent(dbevents.LifecycleEvent{
		EventID:        "evt-1",
		Timestamp:      time.Unix(123, 0).UTC(),
		Kind:           "db_handshake_fail",
		ClientIdentity: "uid:1000",
	})

	if ev.SessionID != "" {
		t.Fatalf("SessionID = %q, want empty for UID client identity", ev.SessionID)
	}
}
