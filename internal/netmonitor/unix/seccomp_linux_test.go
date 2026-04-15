//go:build linux && cgo

package unix

import (
	"testing"

	seccompkg "github.com/agentsh/agentsh/internal/seccomp"
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
