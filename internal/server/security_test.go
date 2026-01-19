package server

import (
	"testing"

	"github.com/agentsh/agentsh/internal/config"
)

func TestDetectAndValidateSecurityMode_AutoMode(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			Mode: "auto",
		},
	}

	mode, caps, err := DetectAndValidateSecurityMode(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if mode == "" {
		t.Error("expected non-empty mode")
	}

	if caps == nil {
		t.Error("expected non-nil caps")
	}
}

func TestDetectAndValidateSecurityMode_StrictFull(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			Mode:   "full",
			Strict: true,
		},
	}

	// This will fail if seccomp/eBPF/FUSE not available
	_, _, err := DetectAndValidateSecurityMode(cfg)

	// We don't assert on error since it depends on the test environment
	// Just verify it doesn't panic
	_ = err
}

func TestDetectAndValidateSecurityMode_MinimumModeViolation(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			Mode:        "minimal",
			MinimumMode: "landlock",
		},
	}

	_, _, err := DetectAndValidateSecurityMode(cfg)

	if err == nil {
		t.Error("expected error when mode doesn't meet minimum requirement")
	}
}

func TestDetectAndValidateSecurityMode_NilConfig(t *testing.T) {
	mode, caps, err := DetectAndValidateSecurityMode(nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should default to auto with detection
	if mode == "" {
		t.Error("expected non-empty mode even with nil config")
	}

	if caps == nil {
		t.Error("expected non-nil caps")
	}
}
