//go:build linux

package ebpf

import "testing"

func TestCheckSupport_ReturnsStatus(t *testing.T) {
	status := CheckSupport()
	if status.Supported {
		// If supported, nothing more to assert here.
		return
	}
	if status.Reason == "" {
		t.Fatalf("expected reason when unsupported")
	}
}
