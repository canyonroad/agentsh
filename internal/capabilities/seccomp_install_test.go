//go:build linux

package capabilities

import "testing"

// Issue #388: SeccompInstallable comes from the real install probe, distinct
// from the read-only Seccomp (kernel-supported) signal.
func TestDetectSecurityCapabilities_SeccompInstallable(t *testing.T) {
	origUN, origInstall := checkSeccompUserNotify, checkSeccompInstall
	defer func() { checkSeccompUserNotify, checkSeccompInstall = origUN, origInstall }()

	checkSeccompUserNotify = func() CheckResult { return CheckResult{Feature: "seccomp-user-notify", Available: true} }
	checkSeccompInstall = func() CheckResult {
		return CheckResult{Feature: "seccomp-install", Available: false, Error: errForTest("EBUSY (errno 16)")}
	}

	caps := DetectSecurityCapabilities()
	if !caps.Seccomp {
		t.Error("Seccomp (kernel-supported) should be true")
	}
	if caps.SeccompInstallable {
		t.Error("SeccompInstallable should be false when the install probe fails")
	}
	if caps.SeccompInstallDetail == "" {
		t.Error("SeccompInstallDetail should carry the failure reason")
	}
}

type testErr string

func (e testErr) Error() string { return string(e) }
func errForTest(s string) error { return testErr(s) }
