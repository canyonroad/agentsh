//go:build linux && cgo

package api

import (
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindReadableAddr_Self(t *testing.T) {
	addr, err := findReadableAddr(os.Getpid())
	require.NoError(t, err, "should find a readable mapping in own process")
	assert.NotZero(t, addr, "address should be non-zero")
}

func TestProbeProcessVMReadvAt_Self(t *testing.T) {
	addr, err := findReadableAddr(os.Getpid())
	require.NoError(t, err)

	err = probeProcessVMReadvAt(os.Getpid(), addr)
	assert.NoError(t, err, "ProcessVMReadv against own PID should succeed")
}

func TestProbeProcMemAt_Self(t *testing.T) {
	addr, err := findReadableAddr(os.Getpid())
	require.NoError(t, err)

	err = probeProcMemAt(os.Getpid(), addr)
	assert.NoError(t, err, "/proc/self/mem read should succeed")
}

func TestProbeMemoryAccess_Self(t *testing.T) {
	pvrErr, memErr := probeMemoryAccess(os.Getpid())
	assert.NoError(t, pvrErr, "ProcessVMReadv should succeed against self")
	assert.NoError(t, memErr, "memErr should be nil when ProcessVMReadv succeeds")
}

func TestProbeMemoryAccess_InvalidPID(t *testing.T) {
	pvrErr, memErr := probeMemoryAccess(999999999)
	assert.Error(t, pvrErr, "should fail for nonexistent PID")
	assert.Error(t, memErr, "fallback should also fail for nonexistent PID")
}

func TestFindReadableAddr_InvalidPID(t *testing.T) {
	_, err := findReadableAddr(999999999)
	assert.Error(t, err, "should fail for nonexistent PID")
}

func TestProbeMemoryAccess_CrossProcess(t *testing.T) {
	// Fork a child process (sleep), probe it from parent, then kill it.
	// This validates the actual access pattern: server reading from wrapper.
	cmd := exec.Command("sleep", "10")
	require.NoError(t, cmd.Start(), "failed to start child process")
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()

	// Give the child a moment to be fully mapped.
	time.Sleep(50 * time.Millisecond)

	pvrErr, memErr := probeMemoryAccess(cmd.Process.Pid)
	assert.NoError(t, pvrErr, "ProcessVMReadv should succeed against child process")
	assert.NoError(t, memErr, "memErr should be nil when ProcessVMReadv succeeds")
}
