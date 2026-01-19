//go:build windows

package capabilities

import (
	"testing"
)

func TestDetect_Windows(t *testing.T) {
	result, err := Detect()
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}

	if result.Platform != "windows" {
		t.Errorf("Platform = %q, want windows", result.Platform)
	}

	// Should have Windows-specific capability keys
	expectedKeys := []string{"app_container", "winfsp", "minifilter"}
	for _, key := range expectedKeys {
		if _, exists := result.Capabilities[key]; !exists {
			t.Errorf("Capabilities missing key %q", key)
		}
	}
}
