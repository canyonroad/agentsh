//go:build linux && cgo

package unix

import (
	"testing"

	"github.com/stretchr/testify/require"
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
