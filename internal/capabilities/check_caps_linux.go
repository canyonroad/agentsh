//go:build linux

package capabilities

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// probeCapabilityDrop reports whether the current process is running with a
// reduced Linux capability set compared to the kernel's maximum. It answers
// the question "is the capability-drop backend actually active for this
// process?" — not "is the capability-drop mechanism available on this
// kernel?". A server running with full CapEff (e.g. started as root without
// dropping caps) is reported as unavailable, because capability-drop is not
// protecting it even though the syscall machinery works.
//
// The probe reads /proc/sys/kernel/cap_last_cap to discover the highest cap
// the running kernel knows about, builds the corresponding full mask, and
// compares it to the effective set from capget(2). When cap_last_cap cannot
// be read (ancient kernels, restricted procfs), the probe falls back to the
// previous permissive behaviour: syscall check only, Available=true with a
// detail flagging the limitation, so deployments on those environments do
// not silently regress.
//
// See golang/go#44312 for why the V3 capget buffer must be a two-element
// array even when callers only care about bits 0..31.
func probeCapabilityDrop() ProbeResult {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return ProbeResult{Available: false, Detail: "capget failed: " + err.Error()}
	}
	if _, _, errno := unix.Syscall6(unix.SYS_PRCTL, unix.PR_CAPBSET_READ, 0, 0, 0, 0, 0); errno != 0 {
		return ProbeResult{Available: false, Detail: "prctl failed: " + errno.Error()}
	}

	lastCap, err := readCapLastCap()
	if err != nil {
		// Very old kernels or unusual procfs restrictions: we can't measure
		// the full mask, so fall back to reporting the mechanism as
		// available with an explicit caveat. This preserves pre-#198
		// behaviour on platforms that genuinely lack the procfs entry.
		return ProbeResult{
			Available: true,
			Detail:    "cap_last_cap unavailable (" + err.Error() + "); mechanism check only",
		}
	}

	dropped, missing, total := capsDropped(data, lastCap)
	if !dropped {
		return ProbeResult{
			Available: false,
			Detail:    fmt.Sprintf("process retains full CapEff (%d/%d caps)", total, total),
		}
	}
	return ProbeResult{
		Available: true,
		Detail:    fmt.Sprintf("%d/%d caps dropped", missing, total),
	}
}

// capFullMask returns the two halves of the V3 effective-capability bitmap
// that has every bit 0..lastCap set. Values outside [0, 63] are clamped:
// negative lastCap yields a zero mask (no caps) and lastCap ≥ 63 yields the
// full 64-bit mask. The layout mirrors unix.CapUserData.Effective so callers
// can compare the return value directly against a capget result.
func capFullMask(lastCap int) (low, high uint32) {
	if lastCap < 0 {
		return 0, 0
	}
	if lastCap >= 63 {
		return 0xFFFF_FFFF, 0xFFFF_FFFF
	}
	if lastCap < 32 {
		// lastCap bits 0..lastCap in the low word. Building the mask via
		// (1<<(lastCap+1))-1 avoids the undefined shift-by-32 edge case.
		return uint32((uint64(1) << uint(lastCap+1)) - 1), 0
	}
	// 32 <= lastCap < 63: low word full, high word gets bits 32..lastCap.
	highBits := uint32((uint64(1) << uint(lastCap-32+1)) - 1)
	return 0xFFFF_FFFF, highBits
}

// capsDropped reports whether the given V3 effective-capability pair has
// fewer bits set than the kernel's full mask for lastCap. It returns:
//
//   - dropped: true iff at least one capability bit within [0, lastCap] is
//     cleared in data.Effective
//   - missing: number of such cleared bits
//   - total:   lastCap + 1, i.e. the count of caps the kernel knows about
//
// Bits above lastCap are deliberately ignored: the kernel should not set
// them, but if it does we must not let that hide a genuine drop of a low
// cap, nor trigger a false positive by flagging phantom high bits as
// "dropped". The helper is pure so it can be unit-tested with synthetic
// CapUserData.
func capsDropped(data [2]unix.CapUserData, lastCap int) (dropped bool, missing int, total int) {
	if lastCap < 0 {
		return false, 0, 0
	}
	if lastCap > 63 {
		lastCap = 63
	}
	total = lastCap + 1

	fullLow, fullHigh := capFullMask(lastCap)
	lowEff := data[0].Effective & fullLow
	highEff := data[1].Effective & fullHigh

	missingLow := fullLow &^ lowEff
	missingHigh := fullHigh &^ highEff
	missing = popcount32(missingLow) + popcount32(missingHigh)
	dropped = missing > 0
	return dropped, missing, total
}

// popcount32 returns the number of set bits in x. The capabilities package
// only uses this helper to report drop counts for detect output, so a
// simple SWAR implementation is plenty — no dependency on math/bits inside
// probe code keeps this file self-contained alongside the other check_*
// probes.
func popcount32(x uint32) int {
	x = x - ((x >> 1) & 0x55555555)
	x = (x & 0x33333333) + ((x >> 2) & 0x33333333)
	x = (x + (x >> 4)) & 0x0f0f0f0f
	return int((x * 0x01010101) >> 24)
}

// readCapLastCap returns the value of /proc/sys/kernel/cap_last_cap, the
// highest capability bit the running kernel recognises. The file has
// existed since Linux 2.6.25 (2008) and contains a single decimal integer
// followed by a newline.
func readCapLastCap() (int, error) {
	b, err := os.ReadFile("/proc/sys/kernel/cap_last_cap")
	if err != nil {
		return 0, err
	}
	s := strings.TrimSpace(string(b))
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("parse cap_last_cap %q: %w", s, err)
	}
	if n < 0 || n > 63 {
		return 0, fmt.Errorf("cap_last_cap out of range: %d", n)
	}
	return n, nil
}
