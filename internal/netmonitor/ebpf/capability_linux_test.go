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

// TestCapBitSet is a regression test for a bug where the word-selection
// logic in hasCap only read the low 32 bits of the effective capability
// mask and returned false for any capability >= bit 32. That includes
// CAP_PERFMON (38) and CAP_BPF (39) — which meant CheckSupport could never
// accept a CAP_BPF-only environment and always fell back to CAP_SYS_ADMIN.
//
// Unlike an integration test against /proc/self/status, this test uses
// synthetic CapUserData values so it reliably exercises the high-word
// branch on every platform, including CI hosts where CAP_BPF is absent
// (the buggy version also returned false for absent caps, so such tests
// couldn't distinguish the fix from the bug).
func TestCapBitSet(t *testing.T) {
	cases := []struct {
		name string
		data [2]unix.CapUserData
		cap  int
		want bool
	}{
		{
			name: "CAP_SYS_ADMIN set in low word",
			data: [2]unix.CapUserData{{Effective: 1 << uint(unix.CAP_SYS_ADMIN)}, {}},
			cap:  unix.CAP_SYS_ADMIN,
			want: true,
		},
		{
			name: "CAP_SYS_ADMIN unset in low word",
			data: [2]unix.CapUserData{{}, {}},
			cap:  unix.CAP_SYS_ADMIN,
			want: false,
		},
		{
			// The buggy pre-fix version read data[0].Effective only and
			// computed bit (39 & 31) = 7 → returned true when low word had
			// bit 7 set even though CAP_BPF (39) was absent. Drive all low
			// bits to force that bug to light up.
			name: "CAP_BPF unset with all low bits set",
			data: [2]unix.CapUserData{{Effective: 0xffffffff}, {Effective: 0}},
			cap:  unix.CAP_BPF,
			want: false,
		},
		{
			// This is the case the buggy version couldn't represent at all:
			// the high word is where CAP_BPF lives, and the buggy code
			// never looked there.
			name: "CAP_BPF set in high word",
			data: [2]unix.CapUserData{{}, {Effective: 1 << uint(unix.CAP_BPF-32)}},
			cap:  unix.CAP_BPF,
			want: true,
		},
		{
			name: "CAP_PERFMON set in high word",
			data: [2]unix.CapUserData{{}, {Effective: 1 << uint(unix.CAP_PERFMON-32)}},
			cap:  unix.CAP_PERFMON,
			want: true,
		},
		{
			name: "CAP_PERFMON unset with CAP_BPF set in high word",
			data: [2]unix.CapUserData{{}, {Effective: 1 << uint(unix.CAP_BPF-32)}},
			cap:  unix.CAP_PERFMON,
			want: false,
		},
		{
			name: "out-of-range cap (negative)",
			data: [2]unix.CapUserData{{Effective: 0xffffffff}, {Effective: 0xffffffff}},
			cap:  -1,
			want: false,
		},
		{
			name: "out-of-range cap (>= 64)",
			data: [2]unix.CapUserData{{Effective: 0xffffffff}, {Effective: 0xffffffff}},
			cap:  64,
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := capBitSet(tc.data, tc.cap)
			if got != tc.want {
				t.Errorf("capBitSet(%+v, %d) = %v, want %v", tc.data, tc.cap, got, tc.want)
			}
		})
	}
}

// TestHasCap_MatchesProcStatus is a secondary integration check: it verifies
// hasCap agrees with /proc/self/status CapEff on this host. It cannot
// distinguish the fixed code from the buggy version (when CAP_BPF is absent
// both report false), so the deterministic regression lives in
// TestCapBitSet — this test just confirms the capget syscall path stays
// consistent with the kernel's own reporting.
func TestHasCap_MatchesProcStatus(t *testing.T) {
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
