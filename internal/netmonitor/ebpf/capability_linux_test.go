//go:build linux

package ebpf

import (
	"os"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

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

// TestHasCap_HighBitsMatchProcStatus is a regression test for a bug where
// hasCap only read the low 32 bits of the effective capability mask and
// returned false for any capability >= bit 32. That includes CAP_BPF (39)
// and CAP_PERFMON (38) — which meant CheckSupport could never accept a
// CAP_BPF-only environment and always fell back to CAP_SYS_ADMIN.
//
// The source of truth for this process's effective capabilities is
// /proc/self/status CapEff (a 64-bit hex value). This test asserts that
// hasCap agrees with CapEff for the specific bits we care about in the
// eBPF capability check. On distros where the test binary has neither
// capability, both sides are false — still a valid consistency check.
func TestHasCap_HighBitsMatchProcStatus(t *testing.T) {
	capEff, err := readProcCapEff()
	if err != nil {
		t.Fatalf("read CapEff: %v", err)
	}

	cases := []struct {
		name string
		bit  int
	}{
		{"CAP_SYS_ADMIN", unix.CAP_SYS_ADMIN}, // bit 21 — low word
		{"CAP_PERFMON", unix.CAP_PERFMON},     // bit 38 — high word
		{"CAP_BPF", unix.CAP_BPF},             // bit 39 — high word
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := capEff&(uint64(1)<<uint(tc.bit)) != 0
			got := hasCap(tc.bit)
			if got != want {
				t.Errorf("hasCap(%s=%d) = %v, want %v (CapEff=0x%016x)", tc.name, tc.bit, got, want, capEff)
			}
		})
	}
}

// readProcCapEff parses CapEff from /proc/self/status. It is intentionally
// independent of the capget-based hasCap so the test exercises both paths.
func readProcCapEff() (uint64, error) {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "CapEff:\t") {
			hex := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:\t"))
			return strconv.ParseUint(hex, 16, 64)
		}
	}
	return 0, nil
}
