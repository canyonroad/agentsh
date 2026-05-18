//go:build linux

package limits

import (
	"strings"
	"testing"
)

func TestCgroupResourceLimitsUnavailableError_Message(t *testing.T) {
	e := &CgroupResourceLimitsUnavailableError{
		Reason: "controllers cpu,memory,pids cannot be enabled in subtree_control: ENOTSUP",
		Limits: CgroupV2Limits{MaxMemoryBytes: 16 << 20, PidsMax: 64},
	}
	msg := e.Error()
	if !strings.Contains(msg, "resource limits unavailable") {
		t.Errorf("missing prefix: %q", msg)
	}
	if !strings.Contains(msg, "ENOTSUP") {
		t.Errorf("missing reason: %q", msg)
	}
	if !strings.Contains(msg, "memory.max=16777216") {
		t.Errorf("missing memory summary: %q", msg)
	}
	if !strings.Contains(msg, "pids.max=64") {
		t.Errorf("missing pids summary: %q", msg)
	}
}
