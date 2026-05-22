//go:build linux && cgo

package unix

import (
	"testing"

	seccompkg "github.com/agentsh/agentsh/internal/seccomp"
	seccomp "github.com/seccomp/libseccomp-golang"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestInstallFilterWithBlocked(t *testing.T) {
	// Note: This test requires root/CAP_SYS_ADMIN to actually install filters.
	// We test the configuration building only.
	cfg := FilterConfig{
		UnixSocketEnabled: true,
		BlockedSyscalls:   []int{101, 165}, // ptrace=101, mount=165 on x86_64
	}

	require.NotEmpty(t, cfg.BlockedSyscalls)
	require.True(t, cfg.UnixSocketEnabled)
}

func TestFilterConfigDefaults(t *testing.T) {
	cfg := DefaultFilterConfig()
	require.True(t, cfg.UnixSocketEnabled)
	require.Empty(t, cfg.BlockedSyscalls) // No blocked syscalls by default
}

func TestFilterClose(t *testing.T) {
	// Test nil filter
	var nilFilter *Filter
	require.NoError(t, nilFilter.Close())

	// Test filter with fd=-1 (no notify fd case)
	noNotifyFilter := &Filter{fd: -1}
	require.NoError(t, noNotifyFilter.Close())
}

func TestFilterConfig_WithExecve(t *testing.T) {
	cfg := FilterConfig{
		UnixSocketEnabled: true,
		ExecveEnabled:     true,
		BlockedSyscalls:   nil,
	}

	// Just test that config is valid and field exists
	// Actual filter installation requires elevated privileges
	// and actual interception tested in integration tests
	require.True(t, cfg.ExecveEnabled)
	require.True(t, cfg.UnixSocketEnabled)
}

// TestInstallFilterWithConfig_WaitKillableOverride asserts that
// FilterConfig.WaitKillable, when non-nil, controls the
// SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV bit on the seccomp(2) flags
// argument regardless of host kernel support.
//
// Issue #369: the operator override path must not be subordinate to the
// kernel-version probe.
func TestInstallFilterWithConfig_WaitKillableOverride(t *testing.T) {
	if err := DetectSupport(); err != nil {
		t.Skipf("seccomp user-notify unsupported on this host: %v", err)
	}
	bt := true
	bf := false
	cases := []struct {
		name     string
		cfgValue *bool
		wantFlag bool
	}{
		{name: "explicit true", cfgValue: &bt, wantFlag: true},
		{name: "explicit false", cfgValue: &bf, wantFlag: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			origLoad := loadFilterSyscall
			origPrctl := prctlSetNoNewPrivs
			t.Cleanup(func() {
				loadFilterSyscall = origLoad
				prctlSetNoNewPrivs = origPrctl
			})

			var capturedFlags uintptr
			loadFilterSyscall = func(flags uintptr, _ *unix.SockFprog) (int, error) {
				capturedFlags = flags
				return 99, nil // pretend success, fd=99
			}
			prctlSetNoNewPrivs = func() error { return nil }

			cfg := FilterConfig{
				UnixSocketEnabled: true,
				WaitKillable:      tc.cfgValue,
			}
			_, err := InstallFilterWithConfig(cfg)
			if err != nil {
				t.Fatalf("install: %v", err)
			}
			gotFlag := capturedFlags&unix.SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV != 0
			if gotFlag != tc.wantFlag {
				t.Fatalf("WAIT_KILLABLE_RECV bit: got %v want %v (flags=0x%x)",
					gotFlag, tc.wantFlag, capturedFlags)
			}
		})
	}
}

func TestInstallFilterWithConfig_OnBlockErrno(t *testing.T) {
	if err := DetectSupport(); err != nil {
		t.Skip("seccomp user-notify not supported:", err)
	}
	cfg := FilterConfig{
		UnixSocketEnabled: true,
		BlockedSyscalls:   []int{int(unix.SYS_PTRACE)},
		OnBlockAction:     seccompkg.OnBlockErrno,
	}
	filt, err := InstallFilterWithConfig(cfg)
	require.NoError(t, err)
	defer filt.Close()
	require.Empty(t, filt.BlockListMap(), "errno mode must not populate blocklist dispatch map")
}

func TestInstallFilterWithConfig_OnBlockKill(t *testing.T) {
	if err := DetectSupport(); err != nil {
		t.Skip("seccomp user-notify not supported:", err)
	}
	cfg := FilterConfig{
		UnixSocketEnabled: true,
		BlockedSyscalls:   []int{int(unix.SYS_PTRACE)},
		OnBlockAction:     seccompkg.OnBlockKill,
	}
	filt, err := InstallFilterWithConfig(cfg)
	require.NoError(t, err)
	defer filt.Close()
	require.Empty(t, filt.BlockListMap(), "kill mode must not populate blocklist dispatch map")
}

func TestInstallFilterWithConfig_OnBlockLog(t *testing.T) {
	if err := DetectSupport(); err != nil {
		t.Skip("seccomp user-notify not supported:", err)
	}
	cfg := FilterConfig{
		UnixSocketEnabled: true,
		BlockedSyscalls:   []int{int(unix.SYS_PTRACE), int(unix.SYS_MOUNT)},
		OnBlockAction:     seccompkg.OnBlockLog,
	}
	filt, err := InstallFilterWithConfig(cfg)
	require.NoError(t, err)
	defer filt.Close()
	m := filt.BlockListMap()
	require.Len(t, m, 2)
	require.Equal(t, seccompkg.OnBlockLog, m[uint32(unix.SYS_PTRACE)])
	require.Equal(t, seccompkg.OnBlockLog, m[uint32(unix.SYS_MOUNT)])
}

func TestInstallFilterWithConfig_OnBlockLogAndKill(t *testing.T) {
	if err := DetectSupport(); err != nil {
		t.Skip("seccomp user-notify not supported:", err)
	}
	cfg := FilterConfig{
		UnixSocketEnabled: true,
		BlockedSyscalls:   []int{int(unix.SYS_PTRACE)},
		OnBlockAction:     seccompkg.OnBlockLogAndKill,
	}
	filt, err := InstallFilterWithConfig(cfg)
	require.NoError(t, err)
	defer filt.Close()
	require.Equal(t, seccompkg.OnBlockLogAndKill, filt.BlockListMap()[uint32(unix.SYS_PTRACE)])
}

func TestInstallFilterWithConfig_UnknownOnBlockDegrades(t *testing.T) {
	if err := DetectSupport(); err != nil {
		t.Skip("seccomp user-notify not supported:", err)
	}
	cfg := FilterConfig{
		UnixSocketEnabled: true,
		BlockedSyscalls:   []int{int(unix.SYS_PTRACE)},
		OnBlockAction:     seccompkg.OnBlockAction("bogus"),
	}
	filt, err := InstallFilterWithConfig(cfg)
	require.NoError(t, err, "unknown action must degrade, not error")
	defer filt.Close()
	require.Empty(t, filt.BlockListMap(), "unknown action must degrade to errno (no notify)")
}

func TestInstallFileMonitorRules_WriteOnlyOpenatUsesFlagConditions(t *testing.T) {
	recorder := &recordingFileRuleAdder{}

	added, err := installFileMonitorRules(recorder, seccomp.ActNotify, true)

	require.NoError(t, err)
	require.Greater(t, added, 0)
	require.False(t, recorder.hasUnconditional(unix.SYS_OPENAT),
		"write-only mode should not trap every openat")
	require.True(t, recorder.hasUnconditional(unix.SYS_OPENAT2),
		"openat2 flags live behind the open_how pointer, so the filter must keep trapping it")
	require.True(t, recorder.hasUnconditional(unix.SYS_UNLINKAT),
		"non-open mutating file syscalls must remain trapped")

	openatConditions := recorder.conditionsFor(unix.SYS_OPENAT)
	require.NotEmpty(t, openatConditions, "write-only mode should install conditional openat rules")
	require.True(t, hasSingleCondition(openatConditions, maskedFlagCondition(2, unix.O_ACCMODE, unix.O_WRONLY)))
	require.True(t, hasSingleCondition(openatConditions, maskedFlagCondition(2, unix.O_ACCMODE, unix.O_RDWR)))
	require.True(t, hasSingleCondition(openatConditions, maskedFlagCondition(2, unix.O_CREAT, unix.O_CREAT)))
	require.True(t, hasSingleCondition(openatConditions, maskedFlagCondition(2, unix.O_TRUNC, unix.O_TRUNC)))
	require.True(t, hasSingleCondition(openatConditions, maskedFlagCondition(2, unix.O_APPEND, unix.O_APPEND)))
	require.True(t, hasSingleCondition(openatConditions, maskedFlagCondition(2, unix.O_TMPFILE, unix.O_TMPFILE)))
}

func TestInstallFileMonitorRules_AllOpenModeTrapsOpenatUnconditionally(t *testing.T) {
	recorder := &recordingFileRuleAdder{}

	added, err := installFileMonitorRules(recorder, seccomp.ActNotify, false)

	require.NoError(t, err)
	require.Greater(t, added, 0)
	require.True(t, recorder.hasUnconditional(unix.SYS_OPENAT))
	require.Empty(t, recorder.conditionsFor(unix.SYS_OPENAT))
}

type recordingFileRuleAdder struct {
	unconditional []recordedFileRule
	conditional   []recordedFileConditionalRule
}

type recordedFileRule struct {
	call   seccomp.ScmpSyscall
	action seccomp.ScmpAction
}

type recordedFileConditionalRule struct {
	call       seccomp.ScmpSyscall
	action     seccomp.ScmpAction
	conditions []seccomp.ScmpCondition
}

func (r *recordingFileRuleAdder) AddRule(call seccomp.ScmpSyscall, action seccomp.ScmpAction) error {
	r.unconditional = append(r.unconditional, recordedFileRule{call: call, action: action})
	return nil
}

func (r *recordingFileRuleAdder) AddRuleConditional(call seccomp.ScmpSyscall, action seccomp.ScmpAction, conditions []seccomp.ScmpCondition) error {
	copied := append([]seccomp.ScmpCondition(nil), conditions...)
	r.conditional = append(r.conditional, recordedFileConditionalRule{
		call:       call,
		action:     action,
		conditions: copied,
	})
	return nil
}

func (r *recordingFileRuleAdder) hasUnconditional(nr int) bool {
	for _, rule := range r.unconditional {
		if rule.call == seccomp.ScmpSyscall(nr) {
			return true
		}
	}
	return false
}

func (r *recordingFileRuleAdder) conditionsFor(nr int) [][]seccomp.ScmpCondition {
	var out [][]seccomp.ScmpCondition
	for _, rule := range r.conditional {
		if rule.call == seccomp.ScmpSyscall(nr) {
			out = append(out, rule.conditions)
		}
	}
	return out
}

func maskedFlagCondition(argument uint, mask, value int) seccomp.ScmpCondition {
	return seccomp.ScmpCondition{
		Argument: argument,
		Op:       seccomp.CompareMaskedEqual,
		Operand1: uint64(mask),
		Operand2: uint64(value),
	}
}

func hasSingleCondition(groups [][]seccomp.ScmpCondition, want seccomp.ScmpCondition) bool {
	for _, conditions := range groups {
		if len(conditions) == 1 && conditions[0] == want {
			return true
		}
	}
	return false
}
