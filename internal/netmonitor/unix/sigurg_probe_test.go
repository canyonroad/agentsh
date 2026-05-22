//go:build linux && cgo

package unix

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestInstallFilter_EmitsWaitKillEngagedOnSupportedKernel re-execs
// the test binary to run InstallFilterWithConfig in a throwaway
// subprocess (because the filter is sticky), then parses the
// subprocess's combined output. It asserts:
//  1. The structured Info line "seccomp: filter loaded ...
//     wait_killable=true" was emitted — proof the kernel accepted
//     the flag through our raw seccomp(2) load path.
//  2. Neither WaitKill-fallback WARN line fired — proof we did NOT
//     silently drop into the EINVAL-retry-without-flag path on a
//     host that should support it.
//
// Together these close the regression surface for Layer 1 under the
// new raw-load architecture, replacing the white-box GetWaitKill
// readback used by the deleted seccomp_waitkill_test.go.
func TestInstallFilter_EmitsWaitKillEngagedOnSupportedKernel(t *testing.T) {
	if os.Getenv(sigurgProbeHelperEnv) == "1" {
		// Re-exec child path: install a minimal filter and exit.
		// Parent asserts on our combined stdout+stderr.
		cfg := FilterConfig{ExecveEnabled: true}
		if _, err := InstallFilterWithConfig(cfg); err != nil {
			t.Fatalf("InstallFilterWithConfig: %v", err)
		}
		return
	}

	if !ProbeWaitKillable() {
		t.Skip("kernel <6.0: WAIT_KILLABLE_RECV not supported on this host")
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	cmd := exec.Command(exe, "-test.run=^TestInstallFilter_EmitsWaitKillEngagedOnSupportedKernel$")
	cmd.Env = append(os.Environ(), sigurgProbeHelperEnv+"=1")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	runErr := cmd.Run()
	combined := out.String()

	if runErr != nil {
		lower := strings.ToLower(combined)
		if strings.Contains(lower, "permission denied") ||
			strings.Contains(lower, "operation not permitted") ||
			strings.Contains(lower, "seccomp not supported") ||
			strings.Contains(lower, "lacks user notify") {
			t.Skipf("host cannot install seccomp filter in this environment; skipping.\nhelper output:\n%s", combined)
		}
		t.Fatalf("sigurg probe subprocess failed: %v\ncombined output:\n%s", runErr, combined)
	}

	hasTextFmt := strings.Contains(combined, `wait_killable=true`)
	hasJSONFmt := strings.Contains(combined, `"wait_killable":true`)
	if !hasTextFmt && !hasJSONFmt {
		t.Fatalf("startup log did not announce wait_killable=true — Layer 1 silently disabled.\ncombined output:\n%s", combined)
	}
	if strings.Contains(combined, "WaitKillable rejected at filter load time") {
		t.Fatalf("Layer 1 fell back at filter load time on a kernel >=6.0 — SIGURG fix degraded.\ncombined output:\n%s", combined)
	}
}

// sigurgProbeHelperEnv gates the re-exec body of the test. Setting it
// outside this test's parent->child dispatch is unsupported; the child
// will install a seccomp filter in whatever process reads the env var.
const sigurgProbeHelperEnv = "AGENTSH_TEST_SIGURG_PROBE_HELPER"

// TestInstallFilter_HonorsOperatorOverride re-execs the test binary
// with FilterConfig.WaitKillable=&false + WaitKillableSource="config"
// and asserts that:
//  1. The "seccomp: filter loaded" line announces wait_killable=false.
//  2. The wait_killable_source field is "config".
//
// Issue #369 — end-to-end coverage of the operator override path. The
// child runs InstallFilterWithConfig with the override pinned off; the
// parent parses combined stdout+stderr and verifies the structured log
// line carries both fields through the install path even on a kernel
// that would otherwise enable WAIT_KILLABLE_RECV.
func TestInstallFilter_HonorsOperatorOverride(t *testing.T) {
	if os.Getenv(sigurgOverrideHelperEnv) == "1" {
		// Re-exec child path: install a minimal filter with the
		// operator override pinned to false and exit. The parent
		// asserts on combined stdout+stderr.
		cfg := FilterConfig{
			UnixSocketEnabled:  true,
			WaitKillable:       boolPtrLocalSigurg(false),
			WaitKillableSource: "config",
		}
		filt, err := InstallFilterWithConfig(cfg)
		if err != nil {
			t.Fatalf("InstallFilterWithConfig: %v", err)
		}
		_ = filt
		return
	}

	if testing.Short() {
		t.Skip("re-exec test skipped in short mode")
	}
	if !ProbeWaitKillable() {
		t.Skip("kernel <6.0: WAIT_KILLABLE_RECV not supported on this host")
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	cmd := exec.Command(exe, "-test.run=^TestInstallFilter_HonorsOperatorOverride$")
	cmd.Env = append(os.Environ(), sigurgOverrideHelperEnv+"=1")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	runErr := cmd.Run()
	combined := out.String()

	if runErr != nil {
		lower := strings.ToLower(combined)
		if strings.Contains(lower, "permission denied") ||
			strings.Contains(lower, "operation not permitted") ||
			strings.Contains(lower, "seccomp not supported") ||
			strings.Contains(lower, "lacks user notify") {
			t.Skipf("host cannot install seccomp filter in this environment; skipping.\nhelper output:\n%s", combined)
		}
		t.Fatalf("override helper subprocess failed: %v\ncombined output:\n%s", runErr, combined)
	}

	hasWKFalseText := strings.Contains(combined, `wait_killable=false`)
	hasWKFalseJSON := strings.Contains(combined, `"wait_killable":false`)
	if !hasWKFalseText && !hasWKFalseJSON {
		t.Fatalf("operator override not honored at install time — want wait_killable=false in load log.\ncombined output:\n%s", combined)
	}
	hasSrcText := strings.Contains(combined, `wait_killable_source=config`)
	hasSrcJSON := strings.Contains(combined, `"wait_killable_source":"config"`)
	if !hasSrcText && !hasSrcJSON {
		t.Fatalf("wait_killable_source not 'config' in load log — Task 10 plumbing broken.\ncombined output:\n%s", combined)
	}
}

// sigurgOverrideHelperEnv gates the re-exec child body for
// TestInstallFilter_HonorsOperatorOverride. Like sigurgProbeHelperEnv,
// it must not be set outside the parent->child dispatch.
const sigurgOverrideHelperEnv = "AGENTSH_TEST_SIGURG_OVERRIDE_HELPER"

// boolPtrLocalSigurg returns a pointer to v. Local helper to keep the
// override test self-contained without depending on test fixtures
// elsewhere in the package.
func boolPtrLocalSigurg(v bool) *bool { return &v }
