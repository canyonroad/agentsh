package platform

import "testing"

// TestDefaultWindowsOptions verifies WindowsSandboxOptions types are defined
// and DefaultWindowsSandboxOptions returns correct defaults.
// These types must be available on all platforms for cross-compilation.
func TestDefaultWindowsOptions(t *testing.T) {
	opts := DefaultWindowsSandboxOptions()
	if opts == nil {
		t.Fatal("DefaultWindowsSandboxOptions returned nil")
	}
	if !opts.UseAppContainer {
		t.Error("UseAppContainer should default to true")
	}
	if !opts.UseMinifilter {
		t.Error("UseMinifilter should default to true")
	}
	if !opts.FailOnAppContainerError {
		t.Error("FailOnAppContainerError should default to true")
	}
	if opts.NetworkAccess != NetworkNone {
		t.Errorf("NetworkAccess should default to NetworkNone, got %v", opts.NetworkAccess)
	}
}
