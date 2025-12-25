package limits

import (
	"testing"
	"time"
)

func TestResourceLimits_Defaults(t *testing.T) {
	limits := ResourceLimits{}

	if limits.MaxMemoryMB != 0 {
		t.Errorf("MaxMemoryMB should default to 0")
	}
	if limits.CPUQuotaPercent != 0 {
		t.Errorf("CPUQuotaPercent should default to 0")
	}
	if limits.MaxProcesses != 0 {
		t.Errorf("MaxProcesses should default to 0")
	}
}

func TestResourceLimits_Values(t *testing.T) {
	limits := ResourceLimits{
		MaxMemoryMB:      512,
		MaxSwapMB:        256,
		CPUQuotaPercent:  50,
		CPUPeriodUS:      100000,
		CPUShares:        1024,
		MaxProcesses:     100,
		MaxThreads:       500,
		MaxDiskReadMBps:  100,
		MaxDiskWriteMBps: 50,
		MaxDiskMB:        10000,
		MaxNetSendMBps:   100,
		MaxNetRecvMBps:   100,
		MaxNetMB:         1000,
		CommandTimeout:   30 * time.Second,
		SessionTimeout:   1 * time.Hour,
	}

	if limits.MaxMemoryMB != 512 {
		t.Errorf("MaxMemoryMB = %d, want 512", limits.MaxMemoryMB)
	}
	if limits.CPUQuotaPercent != 50 {
		t.Errorf("CPUQuotaPercent = %d, want 50", limits.CPUQuotaPercent)
	}
	if limits.CommandTimeout != 30*time.Second {
		t.Errorf("CommandTimeout = %v, want 30s", limits.CommandTimeout)
	}
}

func TestResourceUsage_Zero(t *testing.T) {
	usage := ResourceUsage{}

	if usage.MemoryMB != 0 {
		t.Errorf("MemoryMB should be 0")
	}
	if usage.CPUPercent != 0 {
		t.Errorf("CPUPercent should be 0")
	}
	if usage.ProcessCount != 0 {
		t.Errorf("ProcessCount should be 0")
	}
}

func TestLimitViolation(t *testing.T) {
	violation := LimitViolation{
		Resource: "memory",
		Limit:    512,
		Current:  600,
		Action:   "kill",
	}

	if violation.Resource != "memory" {
		t.Errorf("Resource = %q, want memory", violation.Resource)
	}
	if violation.Limit != 512 {
		t.Errorf("Limit = %d, want 512", violation.Limit)
	}
	if violation.Current != 600 {
		t.Errorf("Current = %d, want 600", violation.Current)
	}
	if violation.Action != "kill" {
		t.Errorf("Action = %q, want kill", violation.Action)
	}
}

func TestLimiterCapabilities(t *testing.T) {
	// Test that zero value has no capabilities
	caps := LimiterCapabilities{}

	if caps.MemoryHard {
		t.Error("MemoryHard should default to false")
	}
	if caps.CPUQuota {
		t.Error("CPUQuota should default to false")
	}
	if caps.ChildTracking {
		t.Error("ChildTracking should default to false")
	}

	// Test with capabilities set
	caps = LimiterCapabilities{
		MemoryHard:    true,
		CPUQuota:      true,
		ProcessCount:  true,
		ChildTracking: true,
	}

	if !caps.MemoryHard {
		t.Error("MemoryHard should be true")
	}
	if !caps.CPUQuota {
		t.Error("CPUQuota should be true")
	}
	if !caps.ChildTracking {
		t.Error("ChildTracking should be true")
	}
}
