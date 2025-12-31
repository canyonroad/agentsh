// internal/policygen/types_test.go
package policygen

import (
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
	if !contains(s, "47 events") {
		t.Errorf("expected '47 events' in %q", s)
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

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
