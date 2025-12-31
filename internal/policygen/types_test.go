// internal/policygen/types_test.go
package policygen

import (
	"strings"
	"testing"
	"time"
)

func TestProvenance_String(t *testing.T) {
	p := Provenance{
		EventCount:  47,
		FirstSeen:   time.Date(2025, 1, 15, 14, 20, 0, 0, time.UTC),
		LastSeen:    time.Date(2025, 1, 15, 14, 31, 45, 0, time.UTC),
		SamplePaths: []string{"/workspace/src/index.ts", "/workspace/src/utils.ts"},
	}
	s := p.String()
	if s == "" {
		t.Error("expected non-empty string")
	}
	if !strings.Contains(s, "47 events") {
		t.Errorf("expected '47 events' in %q", s)
	}
}

func TestProvenance_String_ZeroTimes(t *testing.T) {
	p := Provenance{
		EventCount:  3,
		// FirstSeen and LastSeen are zero values
	}
	s := p.String()
	if s != "3 events" {
		t.Errorf("expected '3 events', got %q", s)
	}
	// Should not contain time range parentheses
	if strings.Contains(s, "(") || strings.Contains(s, ")") {
		t.Errorf("expected no time range for zero times, got %q", s)
	}
}

func TestOptions_Defaults(t *testing.T) {
	opts := DefaultOptions()
	if opts.Threshold != 5 {
		t.Errorf("expected threshold 5, got %d", opts.Threshold)
	}
	if !opts.IncludeBlocked {
		t.Error("expected IncludeBlocked true")
	}
	if !opts.ArgPatterns {
		t.Error("expected ArgPatterns true")
	}
}
