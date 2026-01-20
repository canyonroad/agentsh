//go:build linux && cgo

package unix

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestServeNotify_RoutesExecve(t *testing.T) {
	// Verify the routing logic is correct
	assert.True(t, IsExecveSyscall(unix.SYS_EXECVE))
	assert.True(t, IsExecveSyscall(unix.SYS_EXECVEAT))
	assert.False(t, IsExecveSyscall(unix.SYS_CONNECT))
	assert.False(t, IsExecveSyscall(unix.SYS_SOCKET))
}

func TestGetParentPID(t *testing.T) {
	// Test with current process - parent should be non-zero
	ppid := getParentPID(unix.Getpid())
	assert.Greater(t, ppid, 0, "parent PID should be non-zero for current process")

	// Test with invalid PID - should return 0
	ppid = getParentPID(-1)
	assert.Equal(t, 0, ppid, "parent PID should be 0 for invalid PID")

	// Test with non-existent PID - should return 0
	ppid = getParentPID(999999999)
	assert.Equal(t, 0, ppid, "parent PID should be 0 for non-existent PID")
}
