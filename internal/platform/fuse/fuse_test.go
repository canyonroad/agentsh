// internal/platform/fuse/fuse_test.go

package fuse

import (
	"runtime"
	"testing"
)

func TestInstallInstructions(t *testing.T) {
	instructions := InstallInstructions()
	if instructions == "" {
		t.Error("InstallInstructions returned empty string")
	}

	switch runtime.GOOS {
	case "darwin":
		if instructions != "Install FUSE-T: brew install fuse-t" {
			t.Errorf("unexpected darwin instructions: %s", instructions)
		}
	case "windows":
		if instructions != "Install WinFsp: winget install WinFsp.WinFsp" {
			t.Errorf("unexpected windows instructions: %s", instructions)
		}
	default:
		if instructions != "FUSE not supported on this platform" {
			t.Errorf("unexpected default instructions: %s", instructions)
		}
	}
}

func TestImplementation(t *testing.T) {
	impl := Implementation()
	// Should be one of: fuse-t, macfuse, winfsp, none
	valid := map[string]bool{
		"fuse-t":  true,
		"macfuse": true,
		"winfsp":  true,
		"none":    true,
	}
	if !valid[impl] {
		t.Errorf("unexpected implementation: %s", impl)
	}
}

func TestAvailable(t *testing.T) {
	// Available returns a bool - just verify it doesn't panic
	available := Available()

	// If implementation is "none", available should be false
	impl := Implementation()
	if impl == "none" && available {
		t.Error("Available() returned true but Implementation() is none")
	}
	// If implementation is not "none", available should be true
	if impl != "none" && !available {
		t.Errorf("Available() returned false but Implementation() is %s", impl)
	}
}
