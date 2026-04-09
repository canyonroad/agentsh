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
		"full": true, "ptrace": true, "landlock": true, "landlock-only": true, "minimal": true,
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

	// capabilities_drop must be a bool. Its value depends on whether the
	// process is running with the kernel's full capability set: a root
	// process with CapEff == full mask reports false (nothing dropped),
	// anything less reports true. Prior to the #198 fix this field was
	// hard-coded to true regardless of CapEff, so we only assert the
	// type here and leave value verification to the probe-level tests.
	if _, ok := result.Capabilities["capabilities_drop"].(bool); !ok {
		t.Errorf("capabilities_drop missing or not bool: %T", result.Capabilities["capabilities_drop"])
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
