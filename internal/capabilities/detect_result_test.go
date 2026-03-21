//go:build linux || darwin || windows

package capabilities

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
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

func TestComputeScore_AllAvailable(t *testing.T) {
	domains := []ProtectionDomain{
		{Name: "File Protection", Weight: 25, Backends: []DetectedBackend{{Available: true}}},
		{Name: "Command Control", Weight: 25, Backends: []DetectedBackend{{Available: true}}},
		{Name: "Network", Weight: 20, Backends: []DetectedBackend{{Available: true}}},
		{Name: "Resource Limits", Weight: 15, Backends: []DetectedBackend{{Available: true}}},
		{Name: "Isolation", Weight: 15, Backends: []DetectedBackend{{Available: true}}},
	}
	assert.Equal(t, 100, ComputeScore(domains))
}

func TestComputeScore_NoneAvailable(t *testing.T) {
	domains := []ProtectionDomain{
		{Name: "File Protection", Weight: 25, Backends: []DetectedBackend{{Available: false}}},
		{Name: "Command Control", Weight: 25, Backends: []DetectedBackend{{Available: false}}},
		{Name: "Network", Weight: 20, Backends: []DetectedBackend{{Available: false}}},
		{Name: "Resource Limits", Weight: 15, Backends: []DetectedBackend{{Available: false}}},
		{Name: "Isolation", Weight: 15, Backends: []DetectedBackend{{Available: false}}},
	}
	assert.Equal(t, 0, ComputeScore(domains))
}

func TestComputeScore_Partial(t *testing.T) {
	tests := []struct {
		name     string
		file     bool
		cmd      bool
		net      bool
		res      bool
		iso      bool
		expected int
	}{
		{"File+Command only", true, true, false, false, false, 50},
		{"Network+Resource+Isolation", false, false, true, true, true, 50},
		{"All except Network", true, true, false, true, true, 80},
		{"Only Isolation", false, false, false, false, true, 15},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domains := []ProtectionDomain{
				{Weight: 25, Backends: []DetectedBackend{{Available: tt.file}}},
				{Weight: 25, Backends: []DetectedBackend{{Available: tt.cmd}}},
				{Weight: 20, Backends: []DetectedBackend{{Available: tt.net}}},
				{Weight: 15, Backends: []DetectedBackend{{Available: tt.res}}},
				{Weight: 15, Backends: []DetectedBackend{{Available: tt.iso}}},
			}
			assert.Equal(t, tt.expected, ComputeScore(domains))
		})
	}
}

func TestComputeScore_SingleBackendInMultiBackendDomain(t *testing.T) {
	// One backend available in a multi-backend domain should still score full weight
	domains := []ProtectionDomain{
		{Weight: 25, Backends: []DetectedBackend{
			{Name: "fuse", Available: false},
			{Name: "landlock", Available: true},
			{Name: "seccomp-notify", Available: false},
		}},
	}
	assert.Equal(t, 25, ComputeScore(domains))
}

func TestComputeScore_SetsScoreOnDomains(t *testing.T) {
	domains := []ProtectionDomain{
		{Weight: 25, Backends: []DetectedBackend{{Available: true}}},
		{Weight: 20, Backends: []DetectedBackend{{Available: false}}},
	}
	ComputeScore(domains)
	assert.Equal(t, 25, domains[0].Score)
	assert.Equal(t, 0, domains[1].Score)
}

func TestDetectResult_JSONContainsDomains(t *testing.T) {
	result := &DetectResult{
		Platform:        "linux",
		SecurityMode:    "full",
		ProtectionScore: 100,
		Domains: []ProtectionDomain{
			{Name: "File Protection", Weight: 25, Score: 25, Backends: []DetectedBackend{
				{Name: "fuse", Available: true, Detail: "fusermount3"},
			}},
		},
		Capabilities: map[string]any{"fuse": true},
	}
	data, err := result.JSON()
	assert.NoError(t, err)
	var parsed map[string]any
	assert.NoError(t, json.Unmarshal(data, &parsed))
	assert.Contains(t, parsed, "domains")
	assert.Contains(t, parsed, "capabilities")
}
