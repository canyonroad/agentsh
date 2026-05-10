package events

import (
	"encoding/json"
	"testing"
	"time"
)

func TestLifecycleEvent_JSONRoundTrip(t *testing.T) {
	in := LifecycleEvent{
		EventID:        "01HJ...",
		SessionID:      "sess-1",
		Timestamp:      time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC),
		DBService:      "appdb",
		ClientIdentity: "uid:1000",
		Kind:           "db_listener_auth_fail",
		Reason:         "uid_mismatch",
		PeerUID:        2000,
		PeerPID:        12345,
	}
	bs, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var out LifecycleEvent
	if err := json.Unmarshal(bs, &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if out != in {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", out, in)
	}
}
