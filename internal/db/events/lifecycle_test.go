package events

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestLifecycleEvent_JSONRoundTrip(t *testing.T) {
	in := LifecycleEvent{
		EventID:         "01HJ...",
		SessionID:       "sess-1",
		Timestamp:       time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC),
		DBService:       "appdb",
		ClientIdentity:  "uid:1000",
		Kind:            "db_handshake_fail",
		Reason:          "scram_plus_fail_closed",
		PeerUID:         2000,
		PeerPID:         12345,
		PeerSessionID:   "sess-peer",
		RuleName:        "db-allow",
		BypassMode:      "observe",
		Destination:     "db.internal:5432",
		ProcessID:       23456,
		ProcessIdentity: "psql",
		SuppressedCount: 3,
		ErrorCode:       "SCRAM_PLUS_FAIL_CLOSED",
		SNIHostname:     "db.internal",
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
	if got := string(bs); strings.Contains(got, "sni_hostname") {
		t.Errorf("sni_hostname must be omitted when empty; got %s", got)
	}
}

func TestLifecycleEvent_DegradedReason_RoundTrip(t *testing.T) {
	in := LifecycleEvent{
		EventID:        "01HJ...",
		SessionID:      "sess-1",
		Timestamp:      time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC),
		DBService:      "appdb",
		ClientIdentity: "uid:1000",
		Kind:           "degraded_visibility_warning",
		Reason:         "replication_opt_in",
		DegradedReason: "replication_passthrough",
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

func TestLifecycleEvent_OmitsEmptyDegradedReason(t *testing.T) {
	ev := LifecycleEvent{Kind: "db_handshake_fail", Timestamp: time.Now()}
	bs, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if got := string(bs); strings.Contains(got, "degraded_reason") {
		t.Errorf("degraded_reason must be omitted when empty; got %s", got)
	}
}

func TestLifecycleEvent_OmitsEmptyAuthorizationFields(t *testing.T) {
	ev := LifecycleEvent{Kind: "db_listener_auth_fail", Timestamp: time.Now()}
	bs, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got := string(bs)
	for _, field := range []string{
		"peer_session_id",
		"rule_name",
		"bypass_mode",
		"destination",
		"process_id",
		"process_identity",
		"suppressed_count",
	} {
		if strings.Contains(got, field) {
			t.Errorf("%s must be omitted when empty; got %s", field, got)
		}
	}
}
