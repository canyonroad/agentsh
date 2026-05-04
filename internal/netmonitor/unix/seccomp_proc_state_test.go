//go:build linux && cgo

package unix

import "testing"

// TestParseProcSelfSeccompState_FilterModeWithCount covers the case the
// rc1 #282 diagnostic is meant to confirm: a process running unixwrap
// that has *already* inherited a seccomp filter from its parent. Mode 2
// = SECCOMP_MODE_FILTER, Seccomp_filters > 0 means at least one filter
// chain entry is in place. If the next failing snapshot on Runloop
// shows this state before Load() runs, the EFAULT is confirmed to be
// stacked-install rejection rather than a kernel quirk in F2's content.
func TestParseProcSelfSeccompState_FilterModeWithCount(t *testing.T) {
	const status = `Name:	agentsh-unixwra
Tgid:	123
Pid:	123
PPid:	100
Seccomp:	2
Seccomp_filters:	3
Speculation_Store_Bypass:	thread vulnerable
`
	got := parseProcSelfSeccompState([]byte(status))
	if got.Mode != 2 {
		t.Errorf("Mode: got %d, want 2 (SECCOMP_MODE_FILTER)", got.Mode)
	}
	if got.FilterCount != 3 {
		t.Errorf("FilterCount: got %d, want 3", got.FilterCount)
	}
}

// TestParseProcSelfSeccompState_NoFilters covers a clean parent process
// (no inherited filter) — the contrast case that should appear in the
// FIRST snapshot of any successful run, and would appear in BOTH if the
// double-wrap stacking hypothesis is wrong.
func TestParseProcSelfSeccompState_NoFilters(t *testing.T) {
	const status = `Name:	test
Seccomp:	0
Seccomp_filters:	0
`
	got := parseProcSelfSeccompState([]byte(status))
	if got.Mode != 0 {
		t.Errorf("Mode: got %d, want 0 (SECCOMP_MODE_DISABLED)", got.Mode)
	}
	if got.FilterCount != 0 {
		t.Errorf("FilterCount: got %d, want 0", got.FilterCount)
	}
}

// TestParseProcSelfSeccompState_MissingFilterCount handles older kernels
// (<4.10) that emit Seccomp without Seccomp_filters. The parser must
// not error out — it should report Mode and leave FilterCount at zero
// so the diagnostic snapshot still surfaces useful state.
func TestParseProcSelfSeccompState_MissingFilterCount(t *testing.T) {
	const status = `Name:	test
Seccomp:	2
`
	got := parseProcSelfSeccompState([]byte(status))
	if got.Mode != 2 {
		t.Errorf("Mode: got %d, want 2", got.Mode)
	}
	if got.FilterCount != 0 {
		t.Errorf("FilterCount: got %d, want 0 (field absent)", got.FilterCount)
	}
}

// TestParseProcSelfSeccompState_NeitherField documents the parser's
// behavior when /proc/self/status contains neither Seccomp nor
// Seccomp_filters lines: zero values, Present=false. Used by the
// snapshot helper to distinguish "kernel did not report" from "mode is
// disabled (0)".
func TestParseProcSelfSeccompState_NeitherField(t *testing.T) {
	const status = `Name:	test
Pid:	123
`
	got := parseProcSelfSeccompState([]byte(status))
	if got.Present {
		t.Errorf("Present: got true, want false (no Seccomp line in input)")
	}
	if got.Mode != 0 || got.FilterCount != 0 {
		t.Errorf("got Mode=%d FilterCount=%d, want zero values", got.Mode, got.FilterCount)
	}
}

// TestParseProcSelfSeccompState_PresentTrueWhenSeccompFound documents
// the inverse of TestParseProcSelfSeccompState_NeitherField: if the
// Seccomp: line is parsed at all, Present=true even if the value is 0
// (clean process). Lets the snapshot helper distinguish "kernel
// reported mode 0" from "kernel didn't report".
func TestParseProcSelfSeccompState_PresentTrueWhenSeccompFound(t *testing.T) {
	const status = `Seccomp:	0
Seccomp_filters:	0
`
	got := parseProcSelfSeccompState([]byte(status))
	if !got.Present {
		t.Errorf("Present: got false, want true (Seccomp line present even if 0)")
	}
}
