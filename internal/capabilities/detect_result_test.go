//go:build linux || darwin || windows

package capabilities

import (
	"strings"
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

func TestDetectResult_Table(t *testing.T) {
	result := &DetectResult{
		Platform:        "linux",
		SecurityMode:    "landlock-only",
		ProtectionScore: 80,
		Capabilities: map[string]any{
			"seccomp":          false,
			"landlock":         true,
			"landlock_abi":     4,
			"landlock_network": true,
			"fuse":             false,
		},
		Summary: DetectSummary{
			Available:   []string{"landlock", "landlock_network"},
			Unavailable: []string{"seccomp", "fuse"},
		},
		Tips: []Tip{
			{
				Feature: "fuse",
				Status:  "unavailable",
				Impact:  "Fine-grained filesystem control disabled",
				Action:  "Install FUSE3: pacman -S fuse3",
			},
		},
	}

	table := result.Table()
	if len(table) == 0 {
		t.Error("Table() returned empty")
	}
	// Check key elements are present
	if !strings.Contains(table, "linux") {
		t.Error("Table() missing platform")
	}
	if !strings.Contains(table, "landlock") {
		t.Error("Table() missing landlock")
	}
	if !strings.Contains(table, "fuse") {
		t.Error("Table() missing tip about fuse")
	}
}
