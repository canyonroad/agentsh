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
		Kind:           "db_handshake_fail",
		Reason:         "scram_plus_fail_closed",
		PeerUID:        2000,
		PeerPID:        12345,
		ErrorCode:      "SCRAM_PLUS_FAIL_CLOSED",
		SNIHostname:    "db.internal",
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

func TestLifecycleEvent_OmitsEmptySNIHostname(t *testing.T) {
	ev := LifecycleEvent{Kind: "db_listener_auth_fail", Timestamp: time.Now()}
	bs, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if got := string(bs); contains(got, "sni_hostname") {
		t.Errorf("sni_hostname must be omitted when empty; got %s", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
