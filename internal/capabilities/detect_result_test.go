//go:build linux || darwin || windows

package capabilities

import (
	"testing"
)

func TestDetectResult_JSON(t *testing.T) {
	result := &DetectResult{
		Platform:        "linux",
		SecurityMode:    "landlock-only",
		ProtectionScore: 80,
		Capabilities: map[string]any{
			"landlock":     true,
			"landlock_abi": 4,
		},
		Summary: DetectSummary{
			Available:   []string{"landlock"},
			Unavailable: []string{"seccomp"},
		},
		Tips: []Tip{
			{
				Feature: "seccomp",
				Status:  "unavailable",
				Impact:  "Syscall filtering disabled",
				Action:  "Run on host",
			},
		},
	}

	json, err := result.JSON()
	if err != nil {
		t.Fatalf("JSON() error: %v", err)
	}
	if len(json) == 0 {
		t.Error("JSON() returned empty")
	}
}

func TestDetectResult_YAML(t *testing.T) {
	result := &DetectResult{
		Platform:        "linux",
		SecurityMode:    "minimal",
		ProtectionScore: 50,
		Capabilities:    map[string]any{},
		Summary:         DetectSummary{},
		Tips:            []Tip{},
	}

	yaml, err := result.YAML()
	if err != nil {
		t.Fatalf("YAML() error: %v", err)
	}
	if len(yaml) == 0 {
		t.Error("YAML() returned empty")
	}
}
