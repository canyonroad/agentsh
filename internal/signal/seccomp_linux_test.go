//go:build linux && cgo

package signal

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestSignalSyscalls(t *testing.T) {
	assert.Equal(t, 62, unix.SYS_KILL)
	assert.Equal(t, 234, unix.SYS_TGKILL)
}

func TestSignalFilterConfig(t *testing.T) {
	cfg := DefaultSignalFilterConfig()
	assert.True(t, cfg.Enabled)
	assert.Contains(t, cfg.Syscalls, unix.SYS_KILL)
	assert.Contains(t, cfg.Syscalls, unix.SYS_TGKILL)
	assert.Contains(t, cfg.Syscalls, unix.SYS_TKILL)
}

func TestSignalFilterConfigWithRT(t *testing.T) {
	cfg := DefaultSignalFilterConfig()
	// Also check rt_sigqueueinfo and rt_tgsigqueueinfo
	assert.Contains(t, cfg.Syscalls, unix.SYS_RT_SIGQUEUEINFO)
	assert.Contains(t, cfg.Syscalls, unix.SYS_RT_TGSIGQUEUEINFO)
}

func TestIsSignalSupportAvailable(t *testing.T) {
	// This test just verifies the function exists and returns a boolean
	// The actual value depends on the system
	result := IsSignalSupportAvailable()
	assert.IsType(t, false, result)
}

func TestSignalContextExtraction(t *testing.T) {
	// Test that SignalContext has the expected fields
	ctx := SignalContext{
		PID:       1234,
		Syscall:   unix.SYS_KILL,
		TargetPID: 5678,
		Signal:    15,
	}
	assert.Equal(t, 1234, ctx.PID)
	assert.Equal(t, unix.SYS_KILL, ctx.Syscall)
	assert.Equal(t, 5678, ctx.TargetPID)
	assert.Equal(t, 15, ctx.Signal)
}
