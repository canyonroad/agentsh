//go:build linux && cgo

package unix

import (
	"errors"
	"syscall"
	"testing"
)

func TestClassifyInstallProbe(t *testing.T) {
	cases := []struct {
		name      string
		exitCode  int
		stderr    string
		spawnErr  error
		wantInst  bool
		wantErrno syscall.Errno
	}{
		{"success", 0, "", nil, true, 0},
		{"ebusy", 1, "install filter: ... INSTALL_ERRNO=16\n", nil, false, syscall.EBUSY},
		{"eperm", 1, "INSTALL_ERRNO=1\n", nil, false, syscall.EPERM},
		{"einval", 1, "INSTALL_ERRNO=22\n", nil, false, syscall.EINVAL},
		{"nonerrno_setup_fail", 1, "build filter: boom\n", nil, false, 0},
		{"spawn_error", -1, "", errors.New("fork failed"), false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyInstallProbe(tc.exitCode, tc.stderr, tc.spawnErr)
			if got.Installable != tc.wantInst {
				t.Fatalf("Installable=%v, want %v (detail=%q)", got.Installable, tc.wantInst, got.Detail)
			}
			if got.Errno != tc.wantErrno {
				t.Errorf("Errno=%v (%d), want %v (%d)", got.Errno, got.Errno, tc.wantErrno, tc.wantErrno)
			}
			if !got.Installable && got.Detail == "" {
				t.Error("not-installable result must carry a non-empty Detail")
			}
		})
	}
}

// Real end-to-end: re-exec this test binary as the install-probe child and
// confirm the mechanism runs and returns a coherent verdict. On a kernel that
// supports user-notify the install succeeds; otherwise it reports a recognized
// errno (never a false positive). Skips only if the kernel lacks user-notify.
func TestProbeSeccompInstall_Integration(t *testing.T) {
	if probeSeccompUserNotifyKernel() != nil {
		t.Skip("kernel lacks user-notify; install probe not meaningful here")
	}
	res := ProbeSeccompInstall()
	if !res.Installable && res.Errno == 0 && res.Detail == "" {
		t.Fatalf("incoherent probe result: %+v", res)
	}
	if !res.Installable {
		t.Logf("install not available here: errno=%v detail=%q", res.Errno, res.Detail)
	}
}
