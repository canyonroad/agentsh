package capabilities

import (
	"testing"
)

func TestDetectSecurityCapabilities(t *testing.T) {
	caps := DetectSecurityCapabilities()

	// Should always have Capabilities (can always drop caps)
	if !caps.Capabilities {
		t.Error("Capabilities should always be true")
	}

	// Landlock network requires Landlock available
	if caps.LandlockNetwork && !caps.Landlock {
		t.Error("LandlockNetwork requires Landlock")
	}
}

func TestSecurityCapabilities_SelectMode(t *testing.T) {
	tests := []struct {
		name     string
		caps     SecurityCapabilities
		expected string
	}{
		{
			name: "full mode when all available",
			caps: SecurityCapabilities{
				Seccomp: true, EBPF: true, FUSE: true, Landlock: true,
				Capabilities: true,
			},
			expected: "full",
		},
		{
			name: "landlock mode when seccomp unavailable",
			caps: SecurityCapabilities{
				Seccomp: false, EBPF: false, FUSE: true, Landlock: true,
				Capabilities: true,
			},
			expected: "landlock",
		},
		{
			name: "landlock-only when FUSE also unavailable",
			caps: SecurityCapabilities{
				Seccomp: false, EBPF: false, FUSE: false, Landlock: true,
				Capabilities: true,
			},
			expected: "landlock-only",
		},
		{
			name: "minimal when nothing available",
			caps: SecurityCapabilities{
				Seccomp: false, EBPF: false, FUSE: false, Landlock: false,
				Capabilities: true,
			},
			expected: "minimal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mode := tt.caps.SelectMode()
			if mode != tt.expected {
				t.Errorf("expected mode %q, got %q", tt.expected, mode)
			}
		})
	}
}
