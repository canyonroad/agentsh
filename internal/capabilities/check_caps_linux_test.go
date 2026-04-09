//go:build linux

package capabilities

import (
	"testing"

	"golang.org/x/sys/unix"
)

// TestCapFullMask_LowCapsOnly exercises lastCap values that fit entirely in
// the first uint32 of the V3 capability mask. This catches off-by-one errors
// in the bit-range computation.
func TestCapFullMask_LowCapsOnly(t *testing.T) {
	cases := []struct {
		name     string
		lastCap  int
		wantLow  uint32
		wantHigh uint32
	}{
		{name: "single bit", lastCap: 0, wantLow: 0x0000_0001, wantHigh: 0},
		{name: "first eight", lastCap: 7, wantLow: 0x0000_00FF, wantHigh: 0},
		{name: "boundary 31", lastCap: 31, wantLow: 0xFFFF_FFFF, wantHigh: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			low, high := capFullMask(tc.lastCap)
			if low != tc.wantLow || high != tc.wantHigh {
				t.Errorf("capFullMask(%d) = (%#08x, %#08x); want (%#08x, %#08x)",
					tc.lastCap, low, high, tc.wantLow, tc.wantHigh)
			}
		})
	}
}

// TestCapFullMask_HighCaps exercises the second uint32 for caps 32-63. The
// #196 incident was a 32-bit truncation bug in a sibling helper; keep this
// table to ensure the analogous logic here stays correct for CAP_BPF (39),
// CAP_PERFMON (38), and CAP_CHECKPOINT_RESTORE (40).
func TestCapFullMask_HighCaps(t *testing.T) {
	cases := []struct {
		name     string
		lastCap  int
		wantLow  uint32
		wantHigh uint32
	}{
		{name: "cap 32 only", lastCap: 32, wantLow: 0xFFFF_FFFF, wantHigh: 0x0000_0001},
		{name: "cap 39 (CAP_BPF)", lastCap: 39, wantLow: 0xFFFF_FFFF, wantHigh: 0x0000_00FF},
		{name: "cap 40 (checkpoint)", lastCap: 40, wantLow: 0xFFFF_FFFF, wantHigh: 0x0000_01FF},
		{name: "cap 41", lastCap: 41, wantLow: 0xFFFF_FFFF, wantHigh: 0x0000_03FF},
		{name: "cap 63 max", lastCap: 63, wantLow: 0xFFFF_FFFF, wantHigh: 0xFFFF_FFFF},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			low, high := capFullMask(tc.lastCap)
			if low != tc.wantLow || high != tc.wantHigh {
				t.Errorf("capFullMask(%d) = (%#08x, %#08x); want (%#08x, %#08x)",
					tc.lastCap, low, high, tc.wantLow, tc.wantHigh)
			}
		})
	}
}

// TestCapFullMask_OutOfRange ensures the helper clamps nonsensical inputs
// rather than panicking or shifting undefined amounts.
func TestCapFullMask_OutOfRange(t *testing.T) {
	// Negative → zero mask (caller should have rejected upstream).
	if low, high := capFullMask(-1); low != 0 || high != 0 {
		t.Errorf("capFullMask(-1) = (%#x, %#x); want (0, 0)", low, high)
	}
	// > 63 clamps to full 64-bit mask.
	if low, high := capFullMask(100); low != 0xFFFF_FFFF || high != 0xFFFF_FFFF {
		t.Errorf("capFullMask(100) = (%#x, %#x); want (0xFFFFFFFF, 0xFFFFFFFF)", low, high)
	}
}

// TestCapsDropped_FullMaskNotDropped verifies the #198 regression: a process
// whose effective set matches every kernel capability must be reported as
// "not dropped". Previously probeCapabilityDrop only verified capget+prctl
// succeeded, so a root process with CapEff=0x1fffffffff reported "active".
func TestCapsDropped_FullMaskNotDropped(t *testing.T) {
	// Simulate lastCap = 41 (kernel ≥ 6.0), CapEff with bits 0..41 set.
	var data [2]unix.CapUserData
	data[0].Effective = 0xFFFF_FFFF
	data[1].Effective = 0x0000_03FF // bits 32..41

	dropped, missing, total := capsDropped(data, 41)
	if dropped {
		t.Errorf("capsDropped with full CapEff reported dropped=true")
	}
	if missing != 0 {
		t.Errorf("missing = %d; want 0 (no caps dropped)", missing)
	}
	if total != 42 {
		t.Errorf("total = %d; want 42 (lastCap+1)", total)
	}
}

// TestCapsDropped_AllDropped covers the zero-CapEff path (unprivileged user).
func TestCapsDropped_AllDropped(t *testing.T) {
	var data [2]unix.CapUserData // zero value → no caps

	dropped, missing, total := capsDropped(data, 41)
	if !dropped {
		t.Errorf("capsDropped with zero CapEff reported dropped=false")
	}
	if missing != 42 {
		t.Errorf("missing = %d; want 42", missing)
	}
	if total != 42 {
		t.Errorf("total = %d; want 42", total)
	}
}

// TestCapsDropped_OnlyCapBpfCleared exercises the failure mode that blocked
// #196: a high-numbered cap (CAP_BPF, bit 39) being cleared must count as a
// drop. The old hasCap helper truncated to 32 bits and missed this.
func TestCapsDropped_OnlyCapBpfCleared(t *testing.T) {
	var data [2]unix.CapUserData
	data[0].Effective = 0xFFFF_FFFF
	data[1].Effective = 0x0000_03FF &^ (1 << (39 - 32)) // clear CAP_BPF

	dropped, missing, total := capsDropped(data, 41)
	if !dropped {
		t.Errorf("capsDropped with CAP_BPF cleared reported dropped=false")
	}
	if missing != 1 {
		t.Errorf("missing = %d; want 1", missing)
	}
	if total != 42 {
		t.Errorf("total = %d; want 42", total)
	}
}

// TestCapsDropped_SingleLowCapCleared catches off-by-one errors in the low
// half of the comparison.
func TestCapsDropped_SingleLowCapCleared(t *testing.T) {
	var data [2]unix.CapUserData
	data[0].Effective = 0xFFFF_FFFF &^ (1 << 21) // clear CAP_SYS_ADMIN (bit 21)
	data[1].Effective = 0x0000_03FF

	dropped, missing, total := capsDropped(data, 41)
	if !dropped {
		t.Errorf("capsDropped with CAP_SYS_ADMIN cleared reported dropped=false")
	}
	if missing != 1 {
		t.Errorf("missing = %d; want 1", missing)
	}
	if total != 42 {
		t.Errorf("total = %d; want 42", total)
	}
}

// TestCapsDropped_IgnoresBitsAboveLastCap guards against kernel quirks where
// bits beyond cap_last_cap appear set: those must not trigger a false
// "dropped" signal nor count toward the total.
func TestCapsDropped_IgnoresBitsAboveLastCap(t *testing.T) {
	var data [2]unix.CapUserData
	data[0].Effective = 0xFFFF_FFFF
	// All bits in high word set — but lastCap=41 means only 32..41 matter.
	data[1].Effective = 0xFFFF_FFFF

	dropped, missing, total := capsDropped(data, 41)
	if dropped {
		t.Errorf("capsDropped reported dropped=true when extra high bits set")
	}
	if missing != 0 {
		t.Errorf("missing = %d; want 0", missing)
	}
	if total != 42 {
		t.Errorf("total = %d; want 42", total)
	}
}

// TestCapsDropped_LastCap31Boundary exercises the special case where lastCap
// fits exactly in the low word.
func TestCapsDropped_LastCap31Boundary(t *testing.T) {
	var data [2]unix.CapUserData
	data[0].Effective = 0xFFFF_FFFF
	data[1].Effective = 0xFFFF_FFFF // should be ignored

	dropped, missing, total := capsDropped(data, 31)
	if dropped {
		t.Errorf("capsDropped reported dropped=true when low word full and high ignored")
	}
	if missing != 0 {
		t.Errorf("missing = %d; want 0", missing)
	}
	if total != 32 {
		t.Errorf("total = %d; want 32", total)
	}
}

// TestProbeCapabilityDrop_DetailReflectsBehavior is an integration smoke test
// that asserts the real probe returns a non-empty Detail and that its
// Available flag is consistent with the current process's capability state.
// Previously the probe always returned Available=true regardless of CapEff;
// this test guards against that regression for whichever environment the
// test suite runs in.
func TestProbeCapabilityDrop_DetailReflectsBehavior(t *testing.T) {
	r := probeCapabilityDrop()
	if r.Detail == "" {
		t.Error("probeCapabilityDrop returned empty Detail")
	}

	// Read current CapEff and cap_last_cap the same way the probe does, then
	// cross-check Available against that ground truth.
	hdr := &unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(hdr, &data[0]); err != nil {
		t.Skipf("capget failed: %v", err)
	}
	lastCap, err := readCapLastCap()
	if err != nil {
		// On kernels without cap_last_cap the probe falls back to the
		// permissive path; nothing to cross-check here.
		t.Skipf("readCapLastCap failed: %v", err)
	}
	dropped, _, _ := capsDropped(data, lastCap)
	if dropped != r.Available {
		t.Errorf("probe Available = %v but capsDropped = %v (detail: %q)",
			r.Available, dropped, r.Detail)
	}
}
