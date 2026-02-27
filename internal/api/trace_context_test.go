package api

import "testing"

func TestParseTraceparent_Valid(t *testing.T) {
	traceID, spanID, flags, ok := parseTraceparent("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
	if !ok {
		t.Fatal("expected ok")
	}
	if traceID != "0af7651916cd43dd8448eb211c80319c" {
		t.Errorf("traceID = %q", traceID)
	}
	if spanID != "b7ad6b7169203331" {
		t.Errorf("spanID = %q", spanID)
	}
	if flags != "01" {
		t.Errorf("flags = %q", flags)
	}
}

func TestParseTraceparent_UnsampledFlags(t *testing.T) {
	_, _, flags, ok := parseTraceparent("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-00")
	if !ok {
		t.Fatal("expected ok")
	}
	if flags != "00" {
		t.Errorf("flags = %q, want %q", flags, "00")
	}
}

func TestParseTraceparent_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"too few parts", "00-abc-def"},
		{"too many parts", "00-abc-def-01-extra"},
		{"short trace_id", "00-0af765-b7ad6b7169203331-01"},
		{"short span_id", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b-01"},
		{"non-hex trace_id", "00-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-b7ad6b7169203331-01"},
		{"non-hex span_id", "00-0af7651916cd43dd8448eb211c80319c-zzzzzzzzzzzzzzzz-01"},
		{"non-hex flags", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-zz"},
		{"all-zero trace_id", "00-00000000000000000000000000000000-b7ad6b7169203331-01"},
		{"all-zero span_id", "00-0af7651916cd43dd8448eb211c80319c-0000000000000000-01"},
		{"empty", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, ok := parseTraceparent(tt.input)
			if ok {
				t.Errorf("expected !ok for %q", tt.input)
			}
		})
	}
}

func TestIsValidHex(t *testing.T) {
	tests := []struct {
		s      string
		length int
		want   bool
	}{
		{"0af7651916cd43dd8448eb211c80319c", 32, true},
		{"b7ad6b7169203331", 16, true},
		{"01", 2, true},
		{"zz", 2, false},
		{"0af765", 32, false},
		{"", 0, true},
		{"GG", 2, false},
	}
	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			if got := isValidHex(tt.s, tt.length); got != tt.want {
				t.Errorf("isValidHex(%q, %d) = %v, want %v", tt.s, tt.length, got, tt.want)
			}
		})
	}
}
