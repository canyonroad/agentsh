//go:build linux && cgo

package unix

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"

	seccomp "github.com/seccomp/libseccomp-golang"
)

// TestInstallFilterWithConfig_WaitKillEnabled is a white-box regression
// test ensuring Layer 1 of the SIGURG fix is actually compiled in. On
// pre-2.6 libseccomp headers, SCMP_FLTATR_CTL_WAITKILL resolves to
// _SCMP_FLTATR_MIN (a no-op sentinel) and SetWaitKill silently does
// nothing. Combined with the compile-time #error guard in
// seccomp_version_check.go, this test catches any future regression.
//
// The check is purely in-memory (SetWaitKill/GetWaitKill on a detached
// filter): it does NOT require kernel >=6.0. Running on every Linux+cgo
// environment — including older-kernel CI hosts — is the point, because
// the 2.6-header regression is independent of the kernel.
func TestInstallFilterWithConfig_WaitKillEnabled(t *testing.T) {
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
		t.Fatalf("GetWaitKill returned false after SetWaitKill(true) — " +
			"Layer 1 is silently disabled, the kernel flag will NOT be applied. " +
			"Check libseccomp version (want >=2.6) and PKG_CONFIG_PATH.")
	}
}

// TestInstallFilterWithConfig_WaitKillLoadsCleanly verifies end-to-end
// that InstallFilterWithConfig loads a user-notify filter with
// WaitKill intact on a kernel ≥6.0 — i.e., the
// retry-without-WaitKill fallback in loadWithRetryOnWaitKillFailure
// did NOT trigger. Together with
// TestInstallFilterWithConfig_WaitKillEnabled (in-memory
// SetWaitKill/GetWaitKill round-trip) and the unit tests in
// seccomp_retry_test.go (retry logic with an injected loadFn), this
// closes the regression surface for Layer 1 of the SIGURG fix:
//   - headers regression           → caught by #error guard +
//                                    TestInstallFilterWithConfig_WaitKillEnabled
//   - retry-logic regression       → caught by seccomp_retry_test.go
//   - silent-runtime-fallback      → caught here (a Load() that quietly
//                                    takes the retry path on a kernel
//                                    that should accept WaitKill)
//
// Because Load() permanently installs a seccomp filter in the
// calling process and Go's test runner shares process state across
// tests, we re-exec the test binary to run InstallFilterWithConfig
// in a throwaway subprocess, capture its stderr, and assert that
// neither WaitKill-fallback slog.Warn line was emitted.
func TestInstallFilterWithConfig_WaitKillLoadsCleanly(t *testing.T) {
	if os.Getenv(waitKillHelperEnv) == "1" {
		// We've been re-exec'd as the helper by the parent invocation
		// below. Install the filter and exit — the parent inspects
		// our stderr for WaitKill-fallback slog.Warn lines. Keep the
		// notify surface minimal (ExecveEnabled only) so no trapped
		// syscall is hit during normal test-runner exit.
		cfg := FilterConfig{ExecveEnabled: true}
		if _, err := InstallFilterWithConfig(cfg); err != nil {
			t.Fatalf("InstallFilterWithConfig: %v", err)
		}
		return
	}

	if !ProbeWaitKillable() {
		t.Skip("kernel <6.0: WAIT_KILLABLE_RECV not supported")
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	// -test.run pins the child to this same test; the
	// waitKillHelperEnv guard at the top of the function routes the
	// child to the install path instead of re-spawning.
	cmd := exec.Command(exe, "-test.run=^TestInstallFilterWithConfig_WaitKillLoadsCleanly$")
	cmd.Env = append(os.Environ(), waitKillHelperEnv+"=1")
	// Capture stdout AND stderr into the same buffer. The slog.Warn
	// fallback lines go to stderr (default handler), but the Go
	// testing harness writes t.Fatalf/t.Skip output to stdout — if we
	// captured stderr alone, an environmental permission-denied from
	// the child's t.Fatalf would be invisible to the skip logic below
	// and cause a spurious failure on hosts that should skip.
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	runErr := cmd.Run()
	combined := out.String()

	// Distinguish environmental failures (no permission to install a
	// seccomp filter, no libseccomp support in this binary) from a
	// real Layer 1 regression. "seccomp not supported" is the literal
	// error from DetectSupport on a non-cgo/non-Linux build; the
	// EPERM/no_new_privs cases surface as "permission denied" /
	// "operation not permitted" from libseccomp. These messages arrive
	// on the child's stdout (via t.Fatalf in the testing harness),
	// which is why the combined-output capture above matters.
	if runErr != nil {
		lower := strings.ToLower(combined)
		if strings.Contains(lower, "permission denied") ||
			strings.Contains(lower, "operation not permitted") ||
			strings.Contains(lower, "seccomp not supported") ||
			strings.Contains(lower, "lacks user notify") {
			t.Skipf("host cannot install seccomp filter in this environment; skipping end-to-end check.\nhelper output:\n%s", combined)
		}
		t.Fatalf("WaitKill helper subprocess failed: %v\ncombined output:\n%s", runErr, combined)
	}

	// The two fallback paths in seccomp_linux.go each emit a
	// slog.Warn containing "WaitKillable" plus a distinguishing
	// clause. Match on the specific clause so an unrelated future
	// log line containing "WaitKillable" doesn't silently flip this
	// test green.
	if strings.Contains(combined, "WaitKillable rejected at filter load time") {
		t.Fatalf("Layer 1 fell back at Load() time on a kernel ≥6.0 — SIGURG fix degraded.\ncombined output:\n%s", combined)
	}
	if strings.Contains(combined, "WaitKillable unexpectedly unavailable") {
		t.Fatalf("SetWaitKill failed despite ProbeWaitKillable=true.\ncombined output:\n%s", combined)
	}
}

// waitKillHelperEnv gates the re-exec body of
// TestInstallFilterWithConfig_WaitKillLoadsCleanly. Setting it
// outside of that test's parent→child dispatch is unsupported and
// would install a seccomp filter into whatever process reads this
// env var.
const waitKillHelperEnv = "AGENTSH_TEST_WAITKILL_HELPER"
