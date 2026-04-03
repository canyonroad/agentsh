//go:build darwin

package capabilities

import (
	"testing"
)

func TestSelectDarwinMode(t *testing.T) {
	hasMacwrap := checkMacwrap()

	tests := []struct {
		name         string
		caps         map[string]any
		wantMode     string
		wantScore    int
		needsMacwrap bool
	}{
		{"esf wins", map[string]any{"esf": true, "lima_available": true}, "esf", 90, false},
		{"lima second", map[string]any{"esf": false, "lima_available": true}, "lima", 85, false},
		{"dynamic seatbelt", map[string]any{"esf": false, "lima_available": false}, "dynamic-seatbelt", 65, true},
		{"sandbox-exec fallback", map[string]any{"esf": false, "lima_available": false}, "sandbox-exec", 60, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.needsMacwrap && !hasMacwrap {
				t.Skip("agentsh-macwrap not in PATH")
			}
			if !tt.needsMacwrap && hasMacwrap {
				if tt.wantMode == "sandbox-exec" {
					t.Skip("macwrap is in PATH, this tests the no-macwrap path")
				}
			}
			mode, score := selectDarwinMode(tt.caps)
			if mode != tt.wantMode {
				t.Errorf("selectDarwinMode() mode = %q, want %q", mode, tt.wantMode)
			}
			if score != tt.wantScore {
				t.Errorf("selectDarwinMode() score = %d, want %d", score, tt.wantScore)
			}
		})
	}
}

func TestDetect_Darwin(t *testing.T) {
	result, err := Detect()
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}

	if result.Platform != "darwin" {
		t.Errorf("Platform = %q, want darwin", result.Platform)
	}

	// Should have macOS-specific capability keys
	expectedKeys := []string{"sandbox_exec", "esf", "network_extension"}
	for _, key := range expectedKeys {
		if _, exists := result.Capabilities[key]; !exists {
			t.Errorf("Capabilities missing key %q", key)
		}
	}

	// sandbox_exec should always be true (built into macOS)
	if se, ok := result.Capabilities["sandbox_exec"].(bool); !ok || !se {
		t.Error("sandbox_exec should be true")
	}
}
