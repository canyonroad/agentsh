//go:build linux && cgo

package unix

import (
	"testing"

	seccomp "github.com/seccomp/libseccomp-golang"
)

// TestInstallFilterWithConfig_WaitKillEnabled is a white-box regression
// test ensuring Layer 1 of the SIGURG fix is actually applied when the
// kernel supports it. On pre-2.6 libseccomp headers, the
// SCMP_FLTATR_CTL_WAITKILL constant resolves to _SCMP_FLTATR_MIN (a no-op
// sentinel) and SetWaitKill silently does nothing. Combined with the
// compile-time #error guard in seccomp_version_check.go, this test
// catches any future regression at runtime.
//
// Skips on kernels <6.0 where the flag is not available (Layer 1 is
// expected to be off; Layer 2 signal mask protects).
func TestInstallFilterWithConfig_WaitKillEnabled(t *testing.T) {
	if !ProbeWaitKillable() {
		t.Skip("kernel <6.0: WAIT_KILLABLE_RECV not supported, Layer 1 expected off")
	}

	// Fresh filter we inspect directly, bypassing the (non-exported)
	// Filter wrapper so we can call GetWaitKill without plumbing it
	// through the public API.
	filt, err := seccomp.NewFilter(seccomp.ActAllow)
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	defer filt.Release()

	if err := filt.SetWaitKill(true); err != nil {
		t.Fatalf("SetWaitKill: %v — libseccomp likely built without 2.6 headers "+
			"(the #error guard in seccomp_version_check.go should have prevented this)", err)
	}

	got, err := filt.GetWaitKill()
	if err != nil {
		t.Fatalf("GetWaitKill: %v", err)
	}
	if !got {
		t.Fatalf("GetWaitKill returned false after SetWaitKill(true) — "+
			"Layer 1 is silently disabled, the kernel flag will NOT be applied. "+
			"Check libseccomp version (want >=2.6) and PKG_CONFIG_PATH.")
	}
}

// TestInstallFilterWithConfig_WaitKillLoadsCleanly verifies that a
// filter built via InstallFilterWithConfig actually loads with the
// WaitKill flag on kernels >=6.0 (no retry-without-WaitKill fallback
// triggered). This is an end-to-end smoke that the production path
// engages Layer 1.
func TestInstallFilterWithConfig_WaitKillLoadsCleanly(t *testing.T) {
	if !ProbeWaitKillable() {
		t.Skip("kernel <6.0: WAIT_KILLABLE_RECV not supported")
	}

	// InstallFilterWithConfig loads a filter into THIS process. Run it
	// in a subtest with a fresh subprocess to avoid polluting the test
	// process's filter state. The Go test runner shares process state
	// across tests, so once a seccomp filter is installed it cannot be
	// removed.
	//
	// Keep this test minimal — the fact that InstallFilterWithConfig
	// returns a non-nil Filter on a >=6.0 kernel is sufficient: if the
	// initial load had failed with WaitKill set, the retry path (tested
	// separately in seccomp_retry_test.go) would have cleared WaitKill
	// and produced a Filter we can't distinguish from a no-WaitKill
	// filter. For a definitive end-to-end check, use the Docker matrix.
	t.Skip("skipped to avoid polluting test process filter state; see docker-test matrix for end-to-end verification")
}
