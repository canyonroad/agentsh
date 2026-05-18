//go:build linux

package capabilities

import (
	"testing"

	"github.com/agentsh/agentsh/internal/limits"
)

// resetCgroupProbeCache clears the package-level cache between tests.
func resetCgroupProbeCache(t *testing.T) {
	t.Helper()
	prev := cgroupProbeCache
	t.Cleanup(func() { cgroupProbeCache = prev })
}

func TestCheckCgroupsV2ResourceLimits_NestedAvailable(t *testing.T) {
	resetCgroupProbeCache(t)
	cacheCgroupProbe(&limits.CgroupProbeResult{
		Mode:   limits.ModeNested,
		Reason: "test fixture",
	})
	r := realCheckCgroupsV2ResourceLimits()
	if !r.Available {
		t.Errorf("Nested should be Available=true; got %+v", r)
	}
	if r.Feature != "cgroups_v2_resource_limits" {
		t.Errorf("Feature: got %q, want %q", r.Feature, "cgroups_v2_resource_limits")
	}
}

func TestCheckCgroupsV2ResourceLimits_TopLevelAvailable(t *testing.T) {
	resetCgroupProbeCache(t)
	cacheCgroupProbe(&limits.CgroupProbeResult{
		Mode:   limits.ModeTopLevel,
		Reason: "test fixture",
	})
	r := realCheckCgroupsV2ResourceLimits()
	if !r.Available {
		t.Errorf("TopLevel should be Available=true; got %+v", r)
	}
}

func TestCheckCgroupsV2ResourceLimits_AttachOnly_NotAvailable(t *testing.T) {
	resetCgroupProbeCache(t)
	cacheCgroupProbe(&limits.CgroupProbeResult{
		Mode:   limits.ModeAttachOnly,
		Reason: "attach-only test fixture",
	})
	r := realCheckCgroupsV2ResourceLimits()
	if r.Available {
		t.Errorf("AttachOnly should NOT report resource_limits Available; got %+v", r)
	}
}

func TestCheckCgroupsV2ResourceLimits_Unavailable(t *testing.T) {
	resetCgroupProbeCache(t)
	cacheCgroupProbe(&limits.CgroupProbeResult{
		Mode:   limits.ModeUnavailable,
		Reason: "test fixture",
	})
	r := realCheckCgroupsV2ResourceLimits()
	if r.Available {
		t.Errorf("Unavailable should NOT report Available; got %+v", r)
	}
}
