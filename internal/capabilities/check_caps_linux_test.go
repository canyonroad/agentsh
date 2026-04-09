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

// fullCapEff returns a CapUserData array with every bit 0..lastCap set in
// Effective. Test helper for building synthetic "full privileges" inputs.
func fullCapEff(lastCap int) [2]unix.CapUserData {
	low, high := capFullMask(lastCap)
	var data [2]unix.CapUserData
	data[0].Effective = low
	data[1].Effective = high
	return data
}

// TestCapsDropped_FullEffAndBnd verifies the #198 regression: a process
// whose effective AND bounding sets both match every kernel capability
// must be reported as "not dropped". Previously probeCapabilityDrop only
// verified capget+prctl succeeded, so a root process with CapEff=full
// reported "active".
func TestCapsDropped_FullEffAndBnd(t *testing.T) {
	data := fullCapEff(41)
	bndLow, bndHigh := capFullMask(41)

	r := capsDropped(data, bndLow, bndHigh, 41)
	if r.anyDropped() {
		t.Errorf("capsDropped with full eff+bnd reported dropped=true: %+v", r)
	}
	if r.effMissing != 0 || r.bndMissing != 0 {
		t.Errorf("eff=%d bnd=%d; want 0/0", r.effMissing, r.bndMissing)
	}
	if r.total != 42 {
		t.Errorf("total = %d; want 42", r.total)
	}
}

// TestCapsDropped_BoundingOnlyReduced covers the pattern exercised by
// capabilities.DropCapabilities(): PR_CAPBSET_DROP narrows the bounding
// set but leaves the effective set untouched until a subsequent capset.
// A naive CapEff-only check would miss this; we must flag it as dropped.
func TestCapsDropped_BoundingOnlyReduced(t *testing.T) {
	data := fullCapEff(41) // CapEff still full
	bndLow, bndHigh := capFullMask(41)
	// Clear CAP_SYS_ADMIN (21), CAP_BPF (39), CAP_PERFMON (38) from bounding.
	bndLow &^= 1 << 21
	bndHigh &^= 1 << (39 - 32)
	bndHigh &^= 1 << (38 - 32)

	r := capsDropped(data, bndLow, bndHigh, 41)
	if !r.anyDropped() {
		t.Errorf("capsDropped with bounding reduced reported dropped=false: %+v", r)
	}
	if r.effMissing != 0 {
		t.Errorf("effMissing = %d; want 0", r.effMissing)
	}
	if r.bndMissing != 3 {
		t.Errorf("bndMissing = %d; want 3", r.bndMissing)
	}
}

// TestCapsDropped_EffectiveOnlyReduced is the mirror of the bounding-only
// case: CapBnd retains full capability, but CapEff has been lowered via
// capset(). The probe must still report dropped.
func TestCapsDropped_EffectiveOnlyReduced(t *testing.T) {
	var data [2]unix.CapUserData // all zero
	bndLow, bndHigh := capFullMask(41)

	r := capsDropped(data, bndLow, bndHigh, 41)
	if !r.anyDropped() {
		t.Errorf("capsDropped with effective reduced reported dropped=false: %+v", r)
	}
	if r.effMissing != 42 {
		t.Errorf("effMissing = %d; want 42", r.effMissing)
	}
	if r.bndMissing != 0 {
		t.Errorf("bndMissing = %d; want 0", r.bndMissing)
	}
}

// TestCapsDropped_BothReduced covers the typical "dropped and cleared"
// state: both effective and bounding sets have lost some caps.
func TestCapsDropped_BothReduced(t *testing.T) {
	var data [2]unix.CapUserData
	// Effective keeps only CAP_NET_BIND_SERVICE (10) and CAP_CHOWN (0).
	data[0].Effective = (1 << 0) | (1 << 10)

	// Bounding keeps a few more, including the two above plus CAP_BPF (39).
	var bndLow, bndHigh uint32
	bndLow = (1 << 0) | (1 << 10) | (1 << 21)
	bndHigh = 1 << (39 - 32)

	r := capsDropped(data, bndLow, bndHigh, 41)
	if !r.anyDropped() {
		t.Errorf("capsDropped with both sets reduced reported dropped=false: %+v", r)
	}
	if r.effMissing != 40 {
		t.Errorf("effMissing = %d; want 40", r.effMissing)
	}
	if r.bndMissing != 38 {
		t.Errorf("bndMissing = %d; want 38", r.bndMissing)
	}
}

// TestCapsDropped_OnlyCapBpfCleared exercises the failure mode that blocked
// #196: a high-numbered cap (CAP_BPF, bit 39) being cleared must count as a
// drop. The old hasCap helper truncated to 32 bits and missed this.
func TestCapsDropped_OnlyCapBpfCleared(t *testing.T) {
	data := fullCapEff(41)
	data[1].Effective &^= 1 << (39 - 32) // clear CAP_BPF
	bndLow, bndHigh := capFullMask(41)

	r := capsDropped(data, bndLow, bndHigh, 41)
	if !r.anyDropped() {
		t.Errorf("capsDropped with CAP_BPF cleared reported dropped=false: %+v", r)
	}
	if r.effMissing != 1 {
		t.Errorf("effMissing = %d; want 1", r.effMissing)
	}
}

// TestCapsDropped_SingleLowCapCleared catches off-by-one errors in the low
// half of the comparison.
func TestCapsDropped_SingleLowCapCleared(t *testing.T) {
	data := fullCapEff(41)
	data[0].Effective &^= 1 << 21 // clear CAP_SYS_ADMIN (bit 21)
	bndLow, bndHigh := capFullMask(41)

	r := capsDropped(data, bndLow, bndHigh, 41)
	if !r.anyDropped() {
		t.Errorf("capsDropped with CAP_SYS_ADMIN cleared reported dropped=false: %+v", r)
	}
	if r.effMissing != 1 {
		t.Errorf("effMissing = %d; want 1", r.effMissing)
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

	// Bounding set also reports all bits, including phantom high ones.
	var bndLow, bndHigh uint32 = 0xFFFF_FFFF, 0xFFFF_FFFF

	r := capsDropped(data, bndLow, bndHigh, 41)
	if r.anyDropped() {
		t.Errorf("capsDropped reported dropped=true when extra high bits set: %+v", r)
	}
	if r.effMissing != 0 || r.bndMissing != 0 {
		t.Errorf("missing counts non-zero: eff=%d bnd=%d", r.effMissing, r.bndMissing)
	}
	if r.total != 42 {
		t.Errorf("total = %d; want 42", r.total)
	}
}

// TestCapsDropped_LastCap31Boundary exercises the special case where
// lastCap fits exactly in the low word.
func TestCapsDropped_LastCap31Boundary(t *testing.T) {
	data := fullCapEff(31)
	// High-word bits should be ignored entirely.
	data[1].Effective = 0xFFFF_FFFF
	var bndLow uint32 = 0xFFFF_FFFF
	var bndHigh uint32 = 0xFFFF_FFFF

	r := capsDropped(data, bndLow, bndHigh, 31)
	if r.anyDropped() {
		t.Errorf("capsDropped reported dropped=true when low word full and high ignored: %+v", r)
	}
	if r.total != 32 {
		t.Errorf("total = %d; want 32", r.total)
	}
}

// TestCapDropReport_Detail exercises the human-readable detail string for
// each of the three "dropped" flavours so the roborev reviewer's concern
// about misleading detail text stays fixed.
func TestCapDropReport_Detail(t *testing.T) {
	cases := []struct {
		name string
		rep  capDropReport
		want string
	}{
		{
			name: "effective only",
			rep:  capDropReport{effMissing: 3, bndMissing: 0, total: 42},
			want: "3/42 caps dropped from effective",
		},
		{
			name: "bounding only",
			rep:  capDropReport{effMissing: 0, bndMissing: 5, total: 42},
			want: "5/42 caps dropped from bounding",
		},
		{
			name: "both reduced",
			rep:  capDropReport{effMissing: 3, bndMissing: 5, total: 42},
			want: "3/42 dropped (eff) + 5/42 dropped (bnd)",
		},
		{
			name: "none reduced",
			rep:  capDropReport{effMissing: 0, bndMissing: 0, total: 42},
			want: "0/42 caps dropped",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rep.detail(); got != tc.want {
				t.Errorf("detail() = %q; want %q", got, tc.want)
			}
		})
	}
}

// TestProbeCapabilityDrop_DetailReflectsBehavior is an integration smoke
// test that asserts the real probe returns a non-empty Detail and that its
// Available flag is consistent with the current process's capability
// state. Previously the probe always returned Available=true regardless of
// CapEff; this test guards against that regression for whichever
// environment the test suite runs in.
func TestProbeCapabilityDrop_DetailReflectsBehavior(t *testing.T) {
	r := probeCapabilityDrop()
	if r.Detail == "" {
		t.Error("probeCapabilityDrop returned empty Detail")
	}

	// Read current CapEff, CapBnd and cap_last_cap the same way the probe
	// does, then cross-check Available against that ground truth.
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
	bndLow, bndHigh, err := readCapBoundingSet(lastCap)
	if err != nil {
		t.Skipf("readCapBoundingSet failed: %v", err)
	}

	report := capsDropped(data, bndLow, bndHigh, lastCap)
	if report.anyDropped() != r.Available {
		t.Errorf("probe Available = %v but capsDropped anyDropped = %v (detail: %q)",
			r.Available, report.anyDropped(), r.Detail)
	}
}
