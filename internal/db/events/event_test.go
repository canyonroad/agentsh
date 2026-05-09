// internal/db/events/event_test.go
package events

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/db/effects"
)

func TestRedaction_String(t *testing.T) {
	cases := []struct {
		r Redaction
		s string
	}{
		{RedactionNone, "none"},
		{RedactionParametersRedacted, "parameters_redacted"},
		{RedactionFull, "full"},
	}
	for _, tc := range cases {
		if got := tc.r.String(); got != tc.s {
			t.Errorf("Redaction(%d).String() = %q, want %q", tc.r, got, tc.s)
		}
	}
}

func TestParseRedaction(t *testing.T) {
	cases := map[string]Redaction{
		"none":                RedactionNone,
		"parameters_redacted": RedactionParametersRedacted,
		"full":                RedactionFull,
	}
	for in, want := range cases {
		got, ok := ParseRedaction(in)
		if !ok || got != want {
			t.Errorf("ParseRedaction(%q) = %v, %v; want %v, true", in, got, ok, want)
		}
	}
	if _, ok := ParseRedaction("garbage"); ok {
		t.Error("ParseRedaction(garbage) should fail")
	}
}

func TestDBEvent_JSONRoundTrip(t *testing.T) {
	in := DBEvent{
		EventID:    "01HQ-fake",
		SessionID:  "sess-1",
		Timestamp:  time.Date(2026, 5, 8, 10, 0, 0, 0, time.UTC),
		DBService:  "appdb",
		DBFamily:   "postgres",
		DBDialect:  "postgres",
		Effects: []effects.Effect{{Group: effects.GroupRead, Resolution: effects.ResolutionQualified}},
		StatementRedaction: RedactionParametersRedacted,
		ParserBackend:      effects.ParserBackendLibPgQuery,
	}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var out DBEvent
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if out.EventID != in.EventID || out.DBService != in.DBService {
		t.Errorf("round-trip lost fields: %+v", out)
	}
	if out.StatementRedaction != RedactionParametersRedacted {
		t.Errorf("redaction lost: %v", out.StatementRedaction)
	}
}
