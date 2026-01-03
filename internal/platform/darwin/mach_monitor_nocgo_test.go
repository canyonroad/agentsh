//go:build darwin && !cgo

package darwin

import (
	"testing"
)

func TestParseCPUTime(t *testing.T) {
	tests := []struct {
		input    string
		expected uint64 // nanoseconds
	}{
		{"0:00.00", 0},
		{"0:01.00", 1_000_000_000},
		{"0:01.50", 1_500_000_000},
		{"1:30.00", 90_000_000_000},
		{"1:00:00.00", 3600_000_000_000},
		{"1:30:45.50", (1*3600+30*60+45)*1_000_000_000 + 500_000_000},
		{"5.00", 5_000_000_000},       // Just seconds
		{"45.99", 45_990_000_000},     // Seconds with centiseconds
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := parseCPUTime(tt.input)
			if result != tt.expected {
				t.Errorf("parseCPUTime(%q) = %d, want %d", tt.input, result, tt.expected)
			}
		})
	}
}
