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
// kernel?". A server running with the full effective and bounding sets
// (e.g. started as root without any drop) is reported as unavailable,
// because capability-drop is not protecting it even though the syscall
// machinery works.
//
// The probe checks two capability sets:
//
//   - Effective: the set from capget(2). A process whose effective bits are
//     all set can use every kernel capability right now. Clearing bits here
//     reflects runtime privilege reduction via capset(2) or analogous paths.
//
//   - Bounding: the set read bit-by-bit via prctl(PR_CAPBSET_READ). This is
//     the ceiling the process can never regain (even across exec) and is
//     what capabilities.DropCapabilities() narrows via PR_CAPBSET_DROP.
//     Checking Effective alone would miss a process that dropped its
//     bounding set but kept Effective intact (a genuine privilege drop that
//     constrains exec'd children).
//
// If either set has fewer bits set than the full [0, cap_last_cap] mask,
// the probe reports the backend as active. The Detail string names the
// reduced set (effective, bounding, or both) and the drop count so
// operators can see at a glance which lever is in use.
//
// When /proc/sys/kernel/cap_last_cap cannot be read (pre-2.6.25 kernels,
// restricted procfs), the probe falls back to the previous permissive
// behaviour: Available=true with an explicit caveat in Detail, so
// deployments on those environments do not silently regress.
//
// See golang/go#44312 for why the V3 capget buffer must be a two-element
// CapUserData array even when callers only care about bits 0..31.
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

	bndLow, bndHigh, err := readCapBoundingSet(lastCap)
	if err != nil {
		return ProbeResult{
			Available: false,
			Detail:    "prctl(PR_CAPBSET_READ) failed: " + err.Error(),
		}
	}

	report := capsDropped(data, bndLow, bndHigh, lastCap)
	if !report.anyDropped() {
		return ProbeResult{
			Available: false,
			Detail:    fmt.Sprintf("process retains full CapEff and CapBnd (%d/%d caps)", report.total, report.total),
		}
	}
	return ProbeResult{
		Available: true,
		Detail:    report.detail(),
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

// capDropReport holds the per-set drop counts computed by capsDropped. It
// exists so callers can format a single detail string that names which
// capability sets have been narrowed (effective, bounding, or both) without
// the probe function having to juggle four return values.
type capDropReport struct {
	effMissing int
	bndMissing int
	total      int
}

func (r capDropReport) anyDropped() bool {
	return r.effMissing > 0 || r.bndMissing > 0
}

func (r capDropReport) detail() string {
	switch {
	case r.effMissing > 0 && r.bndMissing > 0:
		return fmt.Sprintf("%d/%d dropped (eff) + %d/%d dropped (bnd)",
			r.effMissing, r.total, r.bndMissing, r.total)
	case r.effMissing > 0:
		return fmt.Sprintf("%d/%d caps dropped from effective", r.effMissing, r.total)
	case r.bndMissing > 0:
		return fmt.Sprintf("%d/%d caps dropped from bounding", r.bndMissing, r.total)
	default:
		return fmt.Sprintf("0/%d caps dropped", r.total)
	}
}

// capsDropped compares the process's effective and bounding capability sets
// against the kernel's full mask for lastCap. The effective set is passed
// as the V3 CapUserData array returned by capget(2); the bounding set is
// passed as its (low, high) halves — captured by the caller via
// PR_CAPBSET_READ since capget does not populate it.
//
// Bits above lastCap are deliberately ignored: the kernel should not set
// them, but if it does we must not let that hide a genuine drop of a low
// cap, nor trigger a false positive by flagging phantom high bits as
// "dropped". The helper is pure so it can be unit-tested with synthetic
// CapUserData.
//
// A process whose CapEff is fully reduced but CapBnd is still full (e.g.
// during a transient capset) counts as "dropped" because privilege has
// been reduced; likewise a process that called PR_CAPBSET_DROP without
// touching Effective counts as "dropped" because future transitions are
// constrained. Both are the common agentsh drop patterns.
func capsDropped(data [2]unix.CapUserData, bndLow, bndHigh uint32, lastCap int) capDropReport {
	if lastCap < 0 {
		return capDropReport{}
	}
	if lastCap > 63 {
		lastCap = 63
	}
	total := lastCap + 1

	fullLow, fullHigh := capFullMask(lastCap)

	effLow := data[0].Effective & fullLow
	effHigh := data[1].Effective & fullHigh
	missingEffLow := fullLow &^ effLow
	missingEffHigh := fullHigh &^ effHigh

	bndLowMasked := bndLow & fullLow
	bndHighMasked := bndHigh & fullHigh
	missingBndLow := fullLow &^ bndLowMasked
	missingBndHigh := fullHigh &^ bndHighMasked

	return capDropReport{
		effMissing: popcount32(missingEffLow) + popcount32(missingEffHigh),
		bndMissing: popcount32(missingBndLow) + popcount32(missingBndHigh),
		total:      total,
	}
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

// readCapBoundingSet walks the process's bounding set with PR_CAPBSET_READ
// and returns it as (low, high) uint32 halves matching the layout of
// CapUserData.Effective. capget(2) deliberately does not expose the
// bounding set, so a bit-by-bit walk is the canonical way to read it.
func readCapBoundingSet(lastCap int) (low, high uint32, err error) {
	if lastCap < 0 {
		return 0, 0, nil
	}
	if lastCap > 63 {
		lastCap = 63
	}
	for cap := 0; cap <= lastCap; cap++ {
		r1, _, errno := unix.Syscall6(unix.SYS_PRCTL, unix.PR_CAPBSET_READ, uintptr(cap), 0, 0, 0, 0)
		if errno != 0 {
			// EINVAL means the kernel doesn't recognise this cap number —
			// treat as "not present in bounding set" and keep going so
			// that kernels slightly older than cap_last_cap still yield
			// a usable mask.
			if errno == unix.EINVAL {
				continue
			}
			return 0, 0, fmt.Errorf("PR_CAPBSET_READ cap=%d: %w", cap, errno)
		}
		if r1 != 1 {
			continue
		}
		if cap < 32 {
			low |= 1 << uint(cap)
		} else {
			high |= 1 << uint(cap-32)
		}
	}
	return low, high, nil
}
