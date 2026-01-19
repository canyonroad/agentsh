//go:build linux

package capabilities

import (
	"strings"
	"testing"
)

func TestDetectLandlock(t *testing.T) {
	result := DetectLandlock()

	// Should return a valid result (may or may not be available)
	if result.ABI < 0 || result.ABI > 5 {
		t.Errorf("unexpected ABI version: %d", result.ABI)
	}

	// Network support requires ABI v4+
	if result.NetworkSupport && result.ABI < 4 {
		t.Error("network support claimed but ABI < 4")
	}
}

func TestLandlockResult_String(t *testing.T) {
	tests := []struct {
		name     string
		result   LandlockResult
		contains string
	}{
		{
			name:     "available with network",
			result:   LandlockResult{Available: true, ABI: 4, NetworkSupport: true},
			contains: "ABI v4",
		},
		{
			name:     "unavailable",
			result:   LandlockResult{Available: false, ABI: 0, Error: "not supported"},
			contains: "unavailable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.result.String()
			if !strings.Contains(s, tt.contains) {
				t.Errorf("expected %q to contain %q", s, tt.contains)
			}
		})
	}
}
