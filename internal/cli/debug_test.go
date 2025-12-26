package cli

import (
	"testing"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{30 * time.Second, "30s"},
		{90 * time.Second, "1m 30s"},
		{3661 * time.Second, "1h 1m 1s"},
		{7200 * time.Second, "2h 0m 0s"},
	}

	for _, tt := range tests {
		got := formatDuration(tt.d)
		if got != tt.want {
			t.Errorf("formatDuration(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
}

func TestFormatAge(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{30 * time.Second, "30s ago"},
		{90 * time.Second, "1m ago"},
		{3600 * time.Second, "1h ago"},
	}

	for _, tt := range tests {
		got := formatAge(tt.d)
		if got != tt.want {
			t.Errorf("formatAge(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
}

func TestComputeStats(t *testing.T) {
	sess := types.Session{
		ID:        "test-session",
		State:     types.SessionStateRunning,
		CreatedAt: time.Now().Add(-1 * time.Hour),
	}

	events := []types.Event{
		{Type: "file_read", Policy: &types.PolicyInfo{EffectiveDecision: types.DecisionAllow}},
		{Type: "file_read", Policy: &types.PolicyInfo{EffectiveDecision: types.DecisionAllow}},
		{Type: "file_write", Policy: &types.PolicyInfo{EffectiveDecision: types.DecisionAllow}},
		{Type: "net_connect", Policy: &types.PolicyInfo{EffectiveDecision: types.DecisionDeny}},
		{Type: "exec", Policy: &types.PolicyInfo{EffectiveDecision: types.DecisionApprove}},
	}

	stats := computeStats(sess, events)

	if stats.SessionID != "test-session" {
		t.Errorf("SessionID = %q, want %q", stats.SessionID, "test-session")
	}

	if stats.TotalEvents != 5 {
		t.Errorf("TotalEvents = %d, want 5", stats.TotalEvents)
	}

	if stats.EventCounts["file_read"] != 2 {
		t.Errorf("EventCounts[file_read] = %d, want 2", stats.EventCounts["file_read"])
	}

	if stats.Decisions.Allow != 3 {
		t.Errorf("Decisions.Allow = %d, want 3", stats.Decisions.Allow)
	}

	if stats.Decisions.Deny != 1 {
		t.Errorf("Decisions.Deny = %d, want 1", stats.Decisions.Deny)
	}

	if stats.Decisions.Prompt != 1 {
		t.Errorf("Decisions.Prompt = %d, want 1", stats.Decisions.Prompt)
	}
}

func TestGetString(t *testing.T) {
	m := map[string]any{
		"string_key": "value",
		"int_key":    123,
	}

	if got := getString(m, "string_key"); got != "value" {
		t.Errorf("getString(string_key) = %q, want %q", got, "value")
	}

	if got := getString(m, "int_key"); got != "" {
		t.Errorf("getString(int_key) = %q, want empty", got)
	}

	if got := getString(m, "missing"); got != "" {
		t.Errorf("getString(missing) = %q, want empty", got)
	}
}
