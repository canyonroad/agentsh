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
// kernel?". A server running with the full permitted and bounding sets
// (e.g. started as root without any drop) is reported as unavailable,
// because capability-drop is not protecting it even though the syscall
// machinery works.
//
// The probe checks two capability sets that represent *durable* privilege
// reduction:
//
//   - Permitted (capget): the upper bound the process can reinstate into
//     Effective via capset(2). A reduced Permitted set means the process
//     genuinely cannot regain those capabilities without exec+file-caps.
//
//   - Bounding (PR_CAPBSET_READ): the hard ceiling. A bit cleared here
//     cannot be regained at all, even across exec. This is what
//     capabilities.DropCapabilities() narrows via PR_CAPBSET_DROP, so
//     omitting it would miss agentsh's own drop mechanism.
//
// The Effective set is deliberately excluded from the drop signal even
// though capget returns it: a process can do capset(eff=0, prm=full) and
// instantly restore Effective on the next syscall, so "CapEff reduced but
// CapPrm full" is a transient state, not a privilege drop. Reporting it
// as dropped would recreate the false positive cluster that #198 is
// trying to close.
//
// Detail text names which sets are reduced (permitted, bounding, or both)
// and the drop count so operators can see at a glance which lever is in
// use.
//
// Fallbacks:
//
//  1. If /proc/sys/kernel/cap_last_cap is unreadable (pre-2.6.25 kernels,
//     restricted procfs), the probe reports Available=true with an
//     explicit caveat in Detail — preserving pre-#198 permissive
//     behaviour on those platforms.
//  2. If PR_CAPBSET_READ fails during the bit walk (uncommon; some
//     lockdown or seccomp profiles block the extended prctl args), the
//     probe falls back to the Permitted-only check and notes the
//     bounding-set status as unknown in Detail. This preserves the
//     behaviour expected by environments where the process has dropped
//     its permitted set but bounding reads are blocked.
//
// See golang/go#44312 for why the V3 capget buffer must be a two-element
// CapUserData array even when callers only care about bits 0..31.
// readCapBoundingSet is the package-level hook used by probeCapabilityDrop
// to read the current bounding set. Tests override it to simulate
// environments where PR_CAPBSET_READ is blocked by seccomp/lockdown so
// the degraded-mode fallback can be exercised without affecting any
// other code paths.
var readCapBoundingSet = realReadCapBoundingSet

func probeCapabilityDrop() ProbeResult {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return ProbeResult{Available: false, Detail: "capget failed: " + err.Error()}
	}

	lastCap, err := readCapLastCap()
	if err != nil {
		// Very old kernels or unusual procfs restrictions: we can't
		// measure the full mask, so fall back to reporting the mechanism
		// as available with an explicit caveat. This preserves pre-#198
		// behaviour on platforms that genuinely lack the procfs entry.
		return ProbeResult{
			Available: true,
			Detail:    "cap_last_cap unavailable (" + err.Error() + "); mechanism check only",
		}
	}

	// Note: we deliberately do NOT short-circuit on PR_CAPBSET_READ errors.
	// Environments that block the extended prctl (seccomp, lockdown) must
	// still get a useful answer from the permitted-only fallback below —
	// the second roborev review caught an earlier version of this function
	// that hard-failed here before the fallback could fire.
	bndLow, bndHigh, bndErr := readCapBoundingSet(lastCap)

	report := capsDropped(data, bndLow, bndHigh, bndErr != nil, lastCap)
	if bndErr != nil {
		report.bndErr = bndErr
	}

	if !report.anyDropped() {
		return ProbeResult{
			Available: false,
			Detail:    report.detailNotDropped(),
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
// full 64-bit mask. The layout mirrors unix.CapUserData.Permitted /
// Effective so callers can compare the return value directly against a
// capget result.
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
// capability sets have been narrowed (permitted, bounding, or both)
// without the probe function having to juggle five return values.
//
// bndUnknown is true when the bounding set could not be read (fallback
// path); in that case bndMissing is 0 and the detail text flags the
// unknown status explicitly so operators know the probe ran in
// degraded mode.
type capDropReport struct {
	prmMissing int
	bndMissing int
	total      int
	bndUnknown bool
	bndErr     error // populated only when bndUnknown is true; used for detail text
}

func (r capDropReport) anyDropped() bool {
	return r.prmMissing > 0 || r.bndMissing > 0
}

func (r capDropReport) detail() string {
	switch {
	case r.prmMissing > 0 && r.bndMissing > 0:
		return fmt.Sprintf("%d/%d dropped (prm) + %d/%d dropped (bnd)",
			r.prmMissing, r.total, r.bndMissing, r.total)
	case r.prmMissing > 0 && r.bndUnknown:
		return fmt.Sprintf("%d/%d caps dropped from permitted; bounding unknown (%v)",
			r.prmMissing, r.total, r.bndErr)
	case r.prmMissing > 0:
		return fmt.Sprintf("%d/%d caps dropped from permitted", r.prmMissing, r.total)
	case r.bndMissing > 0:
		return fmt.Sprintf("%d/%d caps dropped from bounding", r.bndMissing, r.total)
	default:
		return fmt.Sprintf("0/%d caps dropped", r.total)
	}
}

// detailNotDropped produces the detail text for the Available=false case.
// When bounding reads failed we include that caveat so the reader knows
// the conclusion is based on the permitted set alone.
func (r capDropReport) detailNotDropped() string {
	if r.bndUnknown {
		return fmt.Sprintf("process retains full CapPrm (%d/%d caps); bounding unknown (%v)",
			r.total, r.total, r.bndErr)
	}
	return fmt.Sprintf("process retains full CapPrm and CapBnd (%d/%d caps)",
		r.total, r.total)
}

// capsDropped compares the process's permitted and bounding capability
// sets against the kernel's full mask for lastCap. The permitted set is
// passed as the V3 CapUserData array returned by capget(2); the bounding
// set is passed as its (low, high) halves — captured by the caller via
// PR_CAPBSET_READ since capget does not populate it.
//
// When bndUnknown is true, the bounding inputs are ignored and the caller
// must also populate bndErr in the returned report so detail text can
// surface the degraded-mode status.
//
// Bits above lastCap are deliberately ignored: the kernel should not set
// them, but if it does we must not let that hide a genuine drop of a low
// cap, nor trigger a false positive by flagging phantom high bits as
// "dropped". The helper is pure so it can be unit-tested with synthetic
// CapUserData.
//
// Effective is *not* consulted: a process with CapEff reduced but CapPrm
// still full can restore its effective set via capset(2) on the next
// syscall, so counting that as a drop would produce the same false
// positives #198 is trying to eliminate.
func capsDropped(data [2]unix.CapUserData, bndLow, bndHigh uint32, bndUnknown bool, lastCap int) capDropReport {
	if lastCap < 0 {
		return capDropReport{}
	}
	if lastCap > 63 {
		lastCap = 63
	}
	total := lastCap + 1

	fullLow, fullHigh := capFullMask(lastCap)

	prmLow := data[0].Permitted & fullLow
	prmHigh := data[1].Permitted & fullHigh
	missingPrmLow := fullLow &^ prmLow
	missingPrmHigh := fullHigh &^ prmHigh
	prmMissing := popcount32(missingPrmLow) + popcount32(missingPrmHigh)

	rep := capDropReport{
		prmMissing: prmMissing,
		total:      total,
		bndUnknown: bndUnknown,
	}
	if bndUnknown {
		return rep
	}

	bndLowMasked := bndLow & fullLow
	bndHighMasked := bndHigh & fullHigh
	missingBndLow := fullLow &^ bndLowMasked
	missingBndHigh := fullHigh &^ bndHighMasked
	rep.bndMissing = popcount32(missingBndLow) + popcount32(missingBndHigh)
	return rep
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

// realReadCapBoundingSet walks the process's bounding set with
// PR_CAPBSET_READ and returns it as (low, high) uint32 halves matching
// the layout of CapUserData.Permitted. capget(2) deliberately does not
// expose the bounding set, so a bit-by-bit walk is the canonical way to
// read it. Exposed for probeCapabilityDrop via the readCapBoundingSet
// package-level hook so tests can substitute a stub.
func realReadCapBoundingSet(lastCap int) (low, high uint32, err error) {
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
