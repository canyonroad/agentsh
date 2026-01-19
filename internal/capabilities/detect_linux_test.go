//go:build linux

package capabilities

import (
	"testing"
)

func TestDetect_Linux(t *testing.T) {
	result, err := Detect()
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}

	if result.Platform != "linux" {
		t.Errorf("Platform = %q, want linux", result.Platform)
	}

	// SecurityMode should be one of the valid modes
	validModes := map[string]bool{
		"full": true, "landlock": true, "landlock-only": true, "minimal": true,
	}
	if !validModes[result.SecurityMode] {
		t.Errorf("SecurityMode = %q, not a valid mode", result.SecurityMode)
	}

	// ProtectionScore should be between 0 and 100
	if result.ProtectionScore < 0 || result.ProtectionScore > 100 {
		t.Errorf("ProtectionScore = %d, want 0-100", result.ProtectionScore)
	}

	// Should have capabilities map with expected keys
	expectedKeys := []string{"seccomp", "landlock", "fuse", "capabilities_drop"}
	for _, key := range expectedKeys {
		if _, exists := result.Capabilities[key]; !exists {
			t.Errorf("Capabilities missing key %q", key)
		}
	}

	// capabilities_drop should always be true
	if cd, ok := result.Capabilities["capabilities_drop"].(bool); !ok || !cd {
		t.Error("capabilities_drop should be true")
	}
}

func TestDetect_Linux_Summary(t *testing.T) {
	result, err := Detect()
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}

	// Summary.Available and Summary.Unavailable should not overlap
	availSet := make(map[string]bool)
	for _, a := range result.Summary.Available {
		availSet[a] = true
	}
	for _, u := range result.Summary.Unavailable {
		if availSet[u] {
			t.Errorf("Feature %q in both Available and Unavailable", u)
		}
	}
}
