//go:build darwin

package capabilities

import (
	"testing"
)

func TestDetect_Darwin(t *testing.T) {
	result, err := Detect()
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}

	if result.Platform != "darwin" {
		t.Errorf("Platform = %q, want darwin", result.Platform)
	}

	// Should have macOS-specific capability keys
	expectedKeys := []string{"sandbox_exec", "fuse_t", "esf"}
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
