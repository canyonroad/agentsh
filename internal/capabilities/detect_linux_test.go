//go:build linux

package capabilities

import (
	"os/exec"
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

func TestApplyWrapperAvailability_Missing(t *testing.T) {
	// Override LookPath to simulate missing wrapper
	orig := wrapperLookPath
	wrapperLookPath = func(file string) (string, error) {
		return "", exec.ErrNotFound
	}
	defer func() { wrapperLookPath = orig }()

	// Build domains with all backends available
	caps := &SecurityCapabilities{
		Seccomp:         true,
		Landlock:        true,
		LandlockABI:     5,
		LandlockNetwork: true,
		FUSE:            true,
		Ptrace:          true,
	}
	caps.FileEnforcement = detectFileEnforcementBackend(caps)
	domains := buildLinuxDomains(caps)

	// Wrapper not found
	found := applyWrapperAvailability(domains, caps)
	if found {
		t.Fatal("applyWrapperAvailability returned true, want false")
	}

	// Check affected backends are unavailable
	for _, d := range domains {
		for _, b := range d.Backends {
			switch b.Name {
			case "seccomp-notify", "landlock", "seccomp-execve", "landlock-network":
				if b.Available {
					t.Errorf("backend %q should be unavailable when wrapper missing", b.Name)
				}
			case "fuse", "ptrace":
				if !b.Available {
					t.Errorf("backend %q should remain available when wrapper missing", b.Name)
				}
			}
		}
	}

	// secCaps fields should be cleared for wrapper-dependent capabilities
	if caps.Seccomp {
		t.Error("Seccomp should be false when wrapper missing")
	}
	if caps.Landlock {
		t.Error("Landlock should be false when wrapper missing")
	}
	if caps.LandlockNetwork {
		t.Error("LandlockNetwork should be false when wrapper missing")
	}

	// FileEnforcement should fall back to fuse
	if caps.FileEnforcement != "fuse" {
		t.Errorf("FileEnforcement = %q, want 'fuse'", caps.FileEnforcement)
	}
}

func TestApplyWrapperAvailability_Missing_NoFUSE(t *testing.T) {
	// Override LookPath to simulate missing wrapper
	orig := wrapperLookPath
	wrapperLookPath = func(file string) (string, error) {
		return "", exec.ErrNotFound
	}
	defer func() { wrapperLookPath = orig }()

	caps := &SecurityCapabilities{
		Seccomp:     true,
		Landlock:    true,
		LandlockABI: 5,
		FUSE:        false,
		Ptrace:      true,
	}
	caps.FileEnforcement = detectFileEnforcementBackend(caps)
	domains := buildLinuxDomains(caps)

	found := applyWrapperAvailability(domains, caps)
	if found {
		t.Fatal("applyWrapperAvailability returned true, want false")
	}

	// FileEnforcement should fall back to none
	if caps.FileEnforcement != "none" {
		t.Errorf("FileEnforcement = %q, want 'none'", caps.FileEnforcement)
	}

	// secCaps fields should be cleared for wrapper-dependent capabilities
	if caps.Seccomp {
		t.Error("Seccomp should be false when wrapper missing")
	}
	if caps.Landlock {
		t.Error("Landlock should be false when wrapper missing")
	}
	if caps.LandlockNetwork {
		t.Error("LandlockNetwork should be false when wrapper missing")
	}
}

func TestApplyWrapperAvailability_Present(t *testing.T) {
	orig := wrapperLookPath
	wrapperLookPath = func(file string) (string, error) {
		return "/usr/local/bin/" + file, nil
	}
	defer func() { wrapperLookPath = orig }()

	caps := &SecurityCapabilities{
		Seccomp:     true,
		Landlock:    true,
		LandlockABI: 5,
		FUSE:        true,
		Ptrace:      true,
	}
	caps.FileEnforcement = detectFileEnforcementBackend(caps)
	domains := buildLinuxDomains(caps)

	found := applyWrapperAvailability(domains, caps)
	if !found {
		t.Fatal("applyWrapperAvailability returned false, want true")
	}

	// All backends should remain as probed
	for _, d := range domains {
		for _, b := range d.Backends {
			switch b.Name {
			case "seccomp-notify", "seccomp-execve", "landlock":
				if !b.Available {
					t.Errorf("backend %q should be available when wrapper present", b.Name)
				}
			}
		}
	}

	// FileEnforcement should be unchanged
	if caps.FileEnforcement != "landlock" {
		t.Errorf("FileEnforcement = %q, want 'landlock'", caps.FileEnforcement)
	}
}

func TestDetect_WrapperMissing_Tip(t *testing.T) {
	// Override LookPath to simulate missing wrapper
	orig := wrapperLookPath
	wrapperLookPath = func(file string) (string, error) {
		if file == "agentsh-unixwrap" {
			return "", exec.ErrNotFound
		}
		return exec.LookPath(file)
	}
	defer func() { wrapperLookPath = orig }()

	result, err := Detect()
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}

	// seccomp-notify, landlock, seccomp-execve, landlock-network should be unavailable
	for _, d := range result.Domains {
		for _, b := range d.Backends {
			switch b.Name {
			case "seccomp-notify", "landlock", "seccomp-execve", "landlock-network":
				if b.Available {
					t.Errorf("backend %q should be unavailable when wrapper missing", b.Name)
				}
			}
		}
	}

	// Wrapper tip should be present
	found := false
	for _, tip := range result.Tips {
		if tip.Feature == "seccomp-wrapper" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected seccomp-wrapper tip when wrapper missing")
	}

	// Flat capabilities should reflect wrapper absence
	if seccomp, ok := result.Capabilities["seccomp"].(bool); ok && seccomp {
		t.Error("capabilities.seccomp should be false when wrapper missing")
	}
	if landlock, ok := result.Capabilities["landlock"].(bool); ok && landlock {
		t.Error("capabilities.landlock should be false when wrapper missing")
	}
	if landlockNet, ok := result.Capabilities["landlock_network"].(bool); ok && landlockNet {
		t.Error("capabilities.landlock_network should be false when wrapper missing")
	}

	// SecurityMode should not be "full" or "landlock*" without wrapper
	if result.SecurityMode == "full" || result.SecurityMode == "landlock" {
		t.Errorf("SecurityMode = %q, should not report full/landlock without wrapper", result.SecurityMode)
	}
}
