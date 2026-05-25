//go:build linux

package capabilities

import (
	"os/exec"
	"strings"
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
		Seccomp:            true,
		SeccompInstallable: true,
		Landlock:           true,
		LandlockABI:        5,
		LandlockNetwork:    true,
		FUSE:               true,
		Ptrace:             true,
		PtraceEnabled:      true,
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
	if caps.SeccompInstallable {
		t.Error("SeccompInstallable should be false when wrapper missing")
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
	if caps.SeccompInstallable {
		t.Error("SeccompInstallable should be false when wrapper missing")
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
		Seccomp:            true,
		SeccompInstallable: true,
		Landlock:           true,
		LandlockABI:        5,
		FUSE:               true,
		Ptrace:             true,
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

func TestBuildLinuxDomains_SeccompInstallFalseFlipsVerdictAndScore(t *testing.T) {
	caps := &SecurityCapabilities{
		Seccomp:              true,  // kernel-supported
		SeccompInstallable:   false, // but install fails here (e.g. Daytona EBUSY)
		SeccompInstallDetail: "EBUSY (errno 16)",
	}
	domains := buildLinuxDomains(caps)

	exec := findBackend(t, domains, "Command Control", "seccomp-execve")
	if exec.Available {
		t.Error("seccomp-execve must be unavailable when install fails")
	}
	if !strings.Contains(exec.Detail, "EBUSY") || !strings.Contains(strings.ToLower(exec.Detail), "kernel") {
		t.Errorf("seccomp-execve detail should name both kernel-support and the errno; got %q", exec.Detail)
	}
	notify := findBackend(t, domains, "File Protection", "seccomp-notify")
	if notify.Available {
		t.Error("seccomp-notify must be unavailable when install fails")
	}

	// #390: a present-but-unengaged ptrace capability does NOT keep Command
	// Control's weight — only an actively-enforcing backend scores.
	caps.Ptrace = true
	caps.PtraceEnabled = false
	ccIdle := findDomain(t, buildLinuxDomains(caps), "Command Control")
	if got := ComputeScore([]ProtectionDomain{ccIdle}); got != 0 {
		t.Errorf("Command Control should score 0 when ptrace is present but not enabled; got %d", got)
	}

	// ptrace actively enforcing (capability present AND enabled) keeps the weight.
	caps.PtraceEnabled = true
	ccActive := findDomain(t, buildLinuxDomains(caps), "Command Control")
	if got := ComputeScore([]ProtectionDomain{ccActive}); got != WeightCommandControl {
		t.Errorf("Command Control should score %d when ptrace is actively enforcing; got %d", WeightCommandControl, got)
	}

	// Neither seccomp installable nor ptrace active -> score 0.
	caps.Ptrace = false
	caps.PtraceEnabled = false
	ccNone := findDomain(t, buildLinuxDomains(caps), "Command Control")
	if ComputeScore([]ProtectionDomain{ccNone}) != 0 {
		t.Error("Command Control should score 0 when neither seccomp-execve nor ptrace is active")
	}
}

func TestBuildLinuxDomains_SeccompInstallTrueKeepsVerdict(t *testing.T) {
	caps := &SecurityCapabilities{Seccomp: true, SeccompInstallable: true}
	domains := buildLinuxDomains(caps)
	if !findBackend(t, domains, "Command Control", "seccomp-execve").Available {
		t.Error("seccomp-execve must be available when install succeeds")
	}
}

func TestBuildLinuxDomains_PtraceBackendReflectsEnforcement(t *testing.T) {
	// Capability present but not enabled in config: not actively enforcing.
	idle := buildLinuxDomains(&SecurityCapabilities{Ptrace: true, PtraceEnabled: false})
	pb := findBackend(t, idle, "Command Control", "ptrace")
	if pb.Available {
		t.Error("ptrace backend must be unavailable when ptrace is a present-but-unengaged capability")
	}
	if pb.Detail != "available, not active (enable ptrace mode)" {
		t.Errorf("ptrace detail = %q, want the actionable not-active message", pb.Detail)
	}

	// Capability present AND enabled: actively enforcing.
	active := buildLinuxDomains(&SecurityCapabilities{Ptrace: true, PtraceEnabled: true})
	ab := findBackend(t, active, "Command Control", "ptrace")
	if !ab.Available {
		t.Error("ptrace backend must be available when ptrace is enabled (actively enforcing)")
	}
	if ab.Detail != "" {
		t.Errorf("ptrace detail = %q, want empty when actively enforcing", ab.Detail)
	}
}

func TestBuildLinuxDomains_CommandActivePriority(t *testing.T) {
	// seccomp installable -> seccomp-execve is the active backend.
	d := buildLinuxDomains(&SecurityCapabilities{SeccompInstallable: true})
	if got := findDomain(t, d, "Command Control").Active; got != "seccomp-execve" {
		t.Errorf("active = %q, want seccomp-execve when seccomp is installable", got)
	}

	// seccomp not installable, ptrace not enforcing -> no active backend.
	d = buildLinuxDomains(&SecurityCapabilities{SeccompInstallable: false, Ptrace: true, PtraceEnabled: false})
	if got := findDomain(t, d, "Command Control").Active; got != "" {
		t.Errorf("active = %q, want empty when nothing enforces command control", got)
	}

	// seccomp not installable, ptrace enforcing (mode==ptrace) -> ptrace active.
	d = buildLinuxDomains(&SecurityCapabilities{SeccompInstallable: false, Ptrace: true, PtraceEnabled: true})
	if got := findDomain(t, d, "Command Control").Active; got != "ptrace" {
		t.Errorf("active = %q, want ptrace when ptrace is the actively-enforcing fallback", got)
	}
}

func findDomain(t *testing.T, domains []ProtectionDomain, name string) ProtectionDomain {
	t.Helper()
	for _, d := range domains {
		if d.Name == name {
			return d
		}
	}
	t.Fatalf("domain %q not found", name)
	return ProtectionDomain{}
}

func findBackend(t *testing.T, domains []ProtectionDomain, domain, backend string) DetectedBackend {
	t.Helper()
	d := findDomain(t, domains, domain)
	for _, b := range d.Backends {
		if b.Name == backend {
			return b
		}
	}
	t.Fatalf("backend %q not found in %q", backend, domain)
	return DetectedBackend{}
}
