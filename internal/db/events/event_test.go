// internal/db/events/event_test.go
package events

import (
	"encoding/json"
	"strings"
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

func TestDBEvent_Extended_RoundTrip(t *testing.T) {
	rows := int64(7)
	in := DBEvent{
		EventID:   "01HJ...",
		SessionID: "sess-1",
		Timestamp: time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC),
		DBService: "appdb",
		DBFamily:  "postgres",
		DBDialect: "postgres",
		Effects:   []effects.Effect{{Group: effects.GroupRead, Resolution: effects.ResolutionQualified}},

		TLS: EventTLS{Mode: "terminate_reissue", ClientSNI: "db.example"},
		Decision: EventDecision{
			Verb:                "allow",
			RuleKind:            "statement",
			RuleName:            "app-allow-read",
			MatchingEffectIndex: 0,
			MatchingEffectGroup: "read",
		},
		Result: EventResult{
			RowsReturned: &rows,
			BytesIn:      9,
			BytesOut:     42,
			LatencyMs:    3,
		},
		TxContext:  EventTxContext{InTransaction: false, DenyAction: "none"},
		Predicates: EventPredicates{HasFilter: true},
	}
	bs, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var out DBEvent
	if err := json.Unmarshal(bs, &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if out.Decision.Verb != "allow" || out.Result.LatencyMs != 3 {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
	if out.Result.RowsReturned == nil || *out.Result.RowsReturned != 7 {
		t.Fatalf("rows_returned lost: %+v", out.Result.RowsReturned)
	}
	if out.Result.RowsAffected != nil {
		t.Fatalf("rows_affected must be nil for null in wire form: %+v",
			out.Result.RowsAffected)
	}
}

func TestDBEvent_Extended_RowsNull(t *testing.T) {
	in := DBEvent{
		EventID:   "01HJ...",
		Timestamp: time.Now().UTC().Truncate(time.Second),
		Result:    EventResult{BytesIn: 9, BytesOut: 0, LatencyMs: 0},
		TxContext: EventTxContext{DenyAction: "none"},
	}
	bs, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(bs), `"rows_returned":null`) {
		t.Fatalf("rows_returned must serialise as null when nil; got %s", bs)
	}
}
