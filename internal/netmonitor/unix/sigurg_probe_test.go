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
