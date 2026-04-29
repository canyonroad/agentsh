//go:build linux && cgo

package unix

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	seccompkg "github.com/agentsh/agentsh/internal/seccomp"
	"golang.org/x/sys/unix"
)

// familyHelperEnv gates the re-exec body inside the family block tests.
// Setting it outside of those tests' parent→child dispatch is unsupported.
const familyHelperEnv = "AGENTSH_TEST_FAMILY_HELPER"

// TestSeccompFamilyBlock_Errno verifies that installing a filter with
// BlockedFamilies = [{AF_ALG, errno}] causes socket(AF_ALG, ...) to return
// EAFNOSUPPORT in the process running with that filter.
//
// The test re-execs itself as a helper subprocess (keyed by familyHelperEnv)
// that installs the filter and calls socket(AF_ALG) via a raw syscall,
// printing the result. This isolates filter installation to the subprocess
// so the test runner's own filter is not affected.
func TestSeccompFamilyBlock_Errno(t *testing.T) {
	if os.Getenv(familyHelperEnv) == familyHelperErrno {
		runFamilyHelperErrno(t)
		return
	}

	if err := DetectSupport(); err != nil {
		t.Skipf("seccomp user-notify not supported: %v", err)
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	cmd := exec.Command(exe, "-test.run=^TestSeccompFamilyBlock_Errno$", "-test.v")
	cmd.Env = append(os.Environ(), familyHelperEnv+"="+familyHelperErrno)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	runErr := cmd.Run()
	combined := out.String()

	if runErr != nil {
		lower := strings.ToLower(combined)
		if strings.Contains(lower, "permission denied") ||
			strings.Contains(lower, "operation not permitted") ||
			strings.Contains(lower, "lacks user notify") {
			t.Skipf("host cannot install seccomp filter; skipping.\nhelper output:\n%s", combined)
		}
		t.Fatalf("helper subprocess failed: %v\noutput:\n%s", runErr, combined)
	}

	if !strings.Contains(combined, "socket_result=EAFNOSUPPORT") &&
		!strings.Contains(combined, "socket_result=address family not supported") &&
		!strings.Contains(combined, "errno=97") {
		t.Errorf("expected socket(AF_ALG) to return EAFNOSUPPORT (errno 97); helper output:\n%s", combined)
	}
}

// runFamilyHelperErrno is the subprocess body for TestSeccompFamilyBlock_Errno.
// It installs the filter and performs a raw socket(AF_ALG) syscall,
// printing the errno so the parent can assert the correct result.
func runFamilyHelperErrno(t *testing.T) {
	t.Helper()
	cfg := FilterConfig{
		BlockedFamilies: []seccompkg.BlockedFamily{
			{Family: unix.AF_ALG, Action: seccompkg.OnBlockErrno, Name: "AF_ALG"},
		},
	}
	filt, err := InstallFilterWithConfig(cfg)
	if err != nil {
		t.Fatalf("InstallFilterWithConfig: %v", err)
	}
	defer filt.Close()

	// Raw syscall so the filter interception is visible at the syscall level.
	fd, _, errno := unix.RawSyscall(unix.SYS_SOCKET, unix.AF_ALG, unix.SOCK_SEQPACKET, 0)
	if fd != ^uintptr(0) {
		// Unexpectedly got a valid fd — close it.
		_ = unix.Close(int(fd))
		fmt.Printf("socket_result=OK (expected EAFNOSUPPORT)\n")
		return
	}
	// Print both the numeric errno and the stringer form so the parent
	// can match either. EAFNOSUPPORT=97 on Linux/amd64.
	fmt.Printf("socket_result=%v (errno=%d)\n", errno, int(errno))
}

// TestSeccompFamilyBlock_Map_Errno verifies that BlockedFamilyMap is empty
// for errno-action families (they use ActErrno, not notify — no dispatch needed).
func TestSeccompFamilyBlock_Map_Errno(t *testing.T) {
	if err := DetectSupport(); err != nil {
		t.Skipf("seccomp user-notify not supported: %v", err)
	}
	cfg := FilterConfig{
		UnixSocketEnabled: true,
		BlockedFamilies: []seccompkg.BlockedFamily{
			{Family: unix.AF_ALG, Action: seccompkg.OnBlockErrno, Name: "AF_ALG"},
		},
	}
	filt, err := InstallFilterWithConfig(cfg)
	if err != nil {
		t.Fatalf("InstallFilterWithConfig: %v", err)
	}
	defer filt.Close()

	m := filt.BlockedFamilyMap()
	if len(m) != 0 {
		t.Errorf("errno-action families must not populate BlockedFamilyMap; got %v", m)
	}
}

// TestSeccompFamilyBlock_Map_Log verifies that log-action families populate
// BlockedFamilyMap with keys for both SYS_SOCKET and SYS_SOCKETPAIR.
func TestSeccompFamilyBlock_Map_Log(t *testing.T) {
	if err := DetectSupport(); err != nil {
		t.Skipf("seccomp user-notify not supported: %v", err)
	}
	cfg := FilterConfig{
		UnixSocketEnabled: true,
		BlockedFamilies: []seccompkg.BlockedFamily{
			{Family: unix.AF_ALG, Action: seccompkg.OnBlockLog, Name: "AF_ALG"},
		},
	}
	filt, err := InstallFilterWithConfig(cfg)
	if err != nil {
		t.Fatalf("InstallFilterWithConfig: %v", err)
	}
	defer filt.Close()

	m := filt.BlockedFamilyMap()
	socketKey := uint64(unix.SYS_SOCKET)<<32 | uint64(unix.AF_ALG)
	socketpairKey := uint64(unix.SYS_SOCKETPAIR)<<32 | uint64(unix.AF_ALG)

	if _, ok := m[socketKey]; !ok {
		t.Errorf("BlockedFamilyMap missing SYS_SOCKET|AF_ALG key; map: %v", m)
	}
	if _, ok := m[socketpairKey]; !ok {
		t.Errorf("BlockedFamilyMap missing SYS_SOCKETPAIR|AF_ALG key; map: %v", m)
	}
	if len(m) != 2 {
		t.Errorf("expected exactly 2 map entries (socket+socketpair for AF_ALG); got %d: %v", len(m), m)
	}
	if m[socketKey].Name != "AF_ALG" {
		t.Errorf("map entry name=%q, want AF_ALG", m[socketKey].Name)
	}
}

// TestSeccompFamilyBlock_Map_LogAndKill verifies that log_and_kill-action families
// also populate BlockedFamilyMap (same dispatch path as log).
func TestSeccompFamilyBlock_Map_LogAndKill(t *testing.T) {
	if err := DetectSupport(); err != nil {
		t.Skipf("seccomp user-notify not supported: %v", err)
	}
	cfg := FilterConfig{
		UnixSocketEnabled: true,
		BlockedFamilies: []seccompkg.BlockedFamily{
			{Family: unix.AF_ALG, Action: seccompkg.OnBlockLogAndKill, Name: "AF_ALG"},
		},
	}
	filt, err := InstallFilterWithConfig(cfg)
	if err != nil {
		t.Fatalf("InstallFilterWithConfig: %v", err)
	}
	defer filt.Close()

	m := filt.BlockedFamilyMap()
	if len(m) != 2 {
		t.Errorf("log_and_kill must populate BlockedFamilyMap; got %d entries: %v", len(m), m)
	}
}

// TestSeccompFamilyBlock_Map_Kill verifies that kill-action families do NOT
// populate BlockedFamilyMap (ActKillProcess, no notify path needed).
func TestSeccompFamilyBlock_Map_Kill(t *testing.T) {
	if err := DetectSupport(); err != nil {
		t.Skipf("seccomp user-notify not supported: %v", err)
	}
	cfg := FilterConfig{
		UnixSocketEnabled: true,
		BlockedFamilies: []seccompkg.BlockedFamily{
			{Family: unix.AF_ALG, Action: seccompkg.OnBlockKill, Name: "AF_ALG"},
		},
	}
	filt, err := InstallFilterWithConfig(cfg)
	if err != nil {
		t.Fatalf("InstallFilterWithConfig: %v", err)
	}
	defer filt.Close()

	m := filt.BlockedFamilyMap()
	if len(m) != 0 {
		t.Errorf("kill-action families must not populate BlockedFamilyMap; got %v", m)
	}
}

// TestSeccompFamilyBlock_Coexistence verifies Section B of the plan:
// with UnixSocketEnabled=true AND BlockedFamilies=[{AF_ALG, errno}],
// an AF_ALG socket returns EAFNOSUPPORT (errno path takes precedence
// over the unconditional ActNotify for socket(2) via libseccomp's
// action-precedence: ERRNO > NOTIFY).
//
// This test installs the filter in-process since it only checks the
// map state, not actual socket calls (which would trap the test runner).
func TestSeccompFamilyBlock_Coexistence_MapState(t *testing.T) {
	if err := DetectSupport(); err != nil {
		t.Skipf("seccomp user-notify not supported: %v", err)
	}
	cfg := FilterConfig{
		UnixSocketEnabled: true,
		BlockedFamilies: []seccompkg.BlockedFamily{
			{Family: unix.AF_ALG, Action: seccompkg.OnBlockErrno, Name: "AF_ALG"},
		},
	}
	filt, err := InstallFilterWithConfig(cfg)
	if err != nil {
		t.Fatalf("InstallFilterWithConfig: %v", err)
	}
	defer filt.Close()

	// The filter should have installed successfully. The important
	// invariant is that BlockedFamilyMap is empty (errno uses ActErrno,
	// not notify) and the notify fd is valid (UnixSocketEnabled).
	m := filt.BlockedFamilyMap()
	if len(m) != 0 {
		t.Errorf("errno-action family must not populate notify dispatch map; got %v", m)
	}
	if filt.NotifFD() < 0 {
		t.Errorf("UnixSocketEnabled=true should produce valid notify fd; got %d", filt.NotifFD())
	}
}

// TestFamilyToScmpAction verifies the helper maps actions to the
// correct libseccomp actions without requiring filter installation.
func TestFamilyToScmpAction(t *testing.T) {
	cases := []struct {
		action  seccompkg.OnBlockAction
		wantErr bool
	}{
		{seccompkg.OnBlockErrno, false},
		{seccompkg.OnBlockKill, false},
		{seccompkg.OnBlockLog, false},
		{seccompkg.OnBlockLogAndKill, false},
		{seccompkg.OnBlockAction("bogus"), true},
	}
	for _, c := range cases {
		_, err := familyToScmpAction(c.action)
		if (err != nil) != c.wantErr {
			t.Errorf("familyToScmpAction(%q): err=%v wantErr=%v", c.action, err, c.wantErr)
		}
	}
}

const familyHelperErrno = "errno"
