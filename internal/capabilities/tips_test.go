//go:build linux || darwin || windows

package capabilities

import (
	"runtime"
	"testing"
)

func TestGenerateTips_Linux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only test")
	}

	caps := map[string]any{
		"seccomp":          false,
		"landlock":         true,
		"landlock_abi":     3,
		"landlock_network": false,
		"fuse":             false,
		"ebpf":             false,
	}

	tips := GenerateTips("linux", caps)

	// Should have tips for missing features
	hasFuseTip := false
	hasNetworkTip := false
	for _, tip := range tips {
		if tip.Feature == "fuse" {
			hasFuseTip = true
			if tip.Action == "" {
				t.Error("fuse tip missing action")
			}
		}
		if tip.Feature == "landlock_network" {
			hasNetworkTip = true
		}
	}

	if !hasFuseTip {
		t.Error("missing fuse tip")
	}
	if !hasNetworkTip {
		t.Error("missing landlock_network tip")
	}
}

func TestGenerateTips_Darwin(t *testing.T) {
	caps := map[string]any{
		"fuse_t":       false,
		"sandbox_exec": true,
		"esf":          false,
	}

	tips := GenerateTips("darwin", caps)

	hasFuseTTip := false
	for _, tip := range tips {
		if tip.Feature == "fuse_t" {
			hasFuseTTip = true
			if tip.Action == "" {
				t.Error("fuse_t tip missing action")
			}
		}
	}

	if !hasFuseTTip {
		t.Error("missing fuse_t tip")
	}
}

func TestGenerateTips_Windows(t *testing.T) {
	caps := map[string]any{
		"app_container": true,
		"winfsp":        false,
		"minifilter":    false,
	}

	tips := GenerateTips("windows", caps)

	hasWinfspTip := false
	for _, tip := range tips {
		if tip.Feature == "winfsp" {
			hasWinfspTip = true
		}
	}

	if !hasWinfspTip {
		t.Error("missing winfsp tip")
	}
}
