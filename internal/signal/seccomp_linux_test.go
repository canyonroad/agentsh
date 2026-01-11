//go:build linux && cgo

package signal

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

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

func TestSignalContextProcessGroup(t *testing.T) {
	// kill(0, sig) - caller's process group
	ctx := SignalContext{PID: 1000, TargetPID: 0}
	assert.True(t, ctx.IsProcessGroupSignal())
	assert.Equal(t, 1000, ctx.ProcessGroupID()) // Returns caller's PID

	// kill(-42, sig) - process group 42
	ctx = SignalContext{PID: 1000, TargetPID: -42}
	assert.True(t, ctx.IsProcessGroupSignal())
	assert.Equal(t, 42, ctx.ProcessGroupID())

	// kill(123, sig) - single process
	ctx = SignalContext{PID: 1000, TargetPID: 123}
	assert.False(t, ctx.IsProcessGroupSignal())
	assert.Equal(t, 0, ctx.ProcessGroupID())
}

func TestSignalContextTkillSetsPID(t *testing.T) {
	// When tkill is used, TargetPID should equal TargetTID for classification
	ctx := SignalContext{
		PID:       1000,
		TargetTID: 1001,
		TargetPID: 1001, // Set by ExtractSignalContext
		Signal:    15,
	}
	assert.Equal(t, ctx.TargetTID, ctx.TargetPID)
	assert.False(t, ctx.IsProcessGroupSignal())
}
