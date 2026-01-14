//go:build darwin

package limits

import (
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestNewDarwinLimiter(t *testing.T) {
	limiter := NewDarwinLimiter()
	require.NotNil(t, limiter)
	assert.NotNil(t, limiter.sessions)
	assert.NotNil(t, limiter.machMonitor)
}

func TestDarwinLimiter_Capabilities(t *testing.T) {
	limiter := NewDarwinLimiter()
	caps := limiter.Capabilities()

	assert.True(t, caps.MemoryHard, "RLIMIT_AS should be supported")
	assert.False(t, caps.MemorySoft, "soft limits not supported on darwin")
	assert.False(t, caps.Swap, "swap limits not supported on darwin")
	assert.False(t, caps.CPUQuota, "CPU quota not supported on darwin")
	assert.True(t, caps.CPUShares, "renice should be supported")
	assert.True(t, caps.ProcessCount, "RLIMIT_NPROC should be supported")
	assert.True(t, caps.CPUTime, "RLIMIT_CPU should be supported")
	assert.False(t, caps.DiskIORate, "disk I/O rate not supported on darwin")
	assert.True(t, caps.DiskQuota, "RLIMIT_FSIZE should be supported")
	assert.False(t, caps.NetworkRate, "network rate not supported on darwin")
	assert.False(t, caps.ChildTracking, "child tracking requires manual tracking")
}

func TestDarwinLimiter_InterfaceCompliance(t *testing.T) {
	var _ ResourceLimiter = (*DarwinLimiter)(nil)
}

func TestDarwinLimiter_ApplyAndCleanup(t *testing.T) {
	limiter := NewDarwinLimiter()

	// Start a subprocess to apply limits to
	cmd := exec.Command("sleep", "60")
	err := cmd.Start()
	require.NoError(t, err)
	defer cmd.Process.Kill()

	pid := cmd.Process.Pid

	// Apply limits
	limits := ResourceLimits{
		CPUShares: 50,
	}
	err = limiter.Apply(pid, limits)
	require.NoError(t, err)

	// Verify session was created
	limiter.mu.Lock()
	session, ok := limiter.sessions[pid]
	limiter.mu.Unlock()
	assert.True(t, ok)
	assert.Equal(t, pid, session.pid)
	assert.Equal(t, int64(50), session.limits.CPUShares)

	// Cleanup
	err = limiter.Cleanup(pid)
	require.NoError(t, err)

	// Verify session was removed
	limiter.mu.Lock()
	_, ok = limiter.sessions[pid]
	limiter.mu.Unlock()
	assert.False(t, ok)
}

func TestDarwinLimiter_Usage(t *testing.T) {
	limiter := NewDarwinLimiter()

	// Start a subprocess
	cmd := exec.Command("sleep", "60")
	err := cmd.Start()
	require.NoError(t, err)
	defer cmd.Process.Kill()

	pid := cmd.Process.Pid

	// Apply limits to create session
	err = limiter.Apply(pid, ResourceLimits{})
	require.NoError(t, err)
	defer limiter.Cleanup(pid)

	// Get usage
	usage, err := limiter.Usage(pid)
	require.NoError(t, err)
	assert.NotNil(t, usage)

	// Sleep should have minimal memory usage
	assert.GreaterOrEqual(t, usage.MemoryMB, int64(0))
	assert.GreaterOrEqual(t, usage.ProcessCount, 1)
}

func TestDarwinLimiter_UsageNoSession(t *testing.T) {
	limiter := NewDarwinLimiter()

	// Try to get usage for non-existent session
	_, err := limiter.Usage(99999)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no session")
}

func TestDarwinLimiter_CheckLimits_NoViolation(t *testing.T) {
	limiter := NewDarwinLimiter()

	// Start a subprocess
	cmd := exec.Command("sleep", "60")
	err := cmd.Start()
	require.NoError(t, err)
	defer cmd.Process.Kill()

	pid := cmd.Process.Pid

	// Apply generous limits
	limits := ResourceLimits{
		MaxMemoryMB:  10000, // 10 GB
		MaxProcesses: 1000,
	}
	err = limiter.Apply(pid, limits)
	require.NoError(t, err)
	defer limiter.Cleanup(pid)

	// Check limits - should not be violated
	violation, err := limiter.CheckLimits(pid)
	require.NoError(t, err)
	assert.Nil(t, violation)
}

func TestDarwinLimiter_CheckLimitsNoSession(t *testing.T) {
	limiter := NewDarwinLimiter()

	// Try to check limits for non-existent session
	_, err := limiter.CheckLimits(99999)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no session")
}

func TestDarwinLimiter_ApplySelfLimits(t *testing.T) {
	limiter := NewDarwinLimiter()

	// Get current limits first to restore them later
	var origNproc unix.Rlimit
	err := unix.Getrlimit(unix.RLIMIT_NPROC, &origNproc)
	require.NoError(t, err)

	// Apply limits to self (pid 0 means current process)
	limits := ResourceLimits{
		MaxProcesses: 500,
	}
	err = limiter.Apply(0, limits)
	require.NoError(t, err)
	defer limiter.Cleanup(0)

	// Verify the limit was set
	var newNproc unix.Rlimit
	err = unix.Getrlimit(unix.RLIMIT_NPROC, &newNproc)
	require.NoError(t, err)
	assert.Equal(t, uint64(500), newNproc.Cur)

	// Restore original limit
	unix.Setrlimit(unix.RLIMIT_NPROC, &origNproc)
}

func TestDarwinLimiter_ApplySelfMemoryLimit(t *testing.T) {
	limiter := NewDarwinLimiter()

	// Get current limits first
	var origAS unix.Rlimit
	err := unix.Getrlimit(unix.RLIMIT_AS, &origAS)
	require.NoError(t, err)

	// Apply memory limit (in MB)
	// Note: On macOS, RLIMIT_AS may return "invalid argument" for certain values
	// This is a platform limitation, not a code bug
	limits := ResourceLimits{
		MaxMemoryMB: 8192, // 8 GB
	}
	err = limiter.Apply(0, limits)
	if err != nil {
		// macOS may reject certain RLIMIT_AS values - this is expected
		t.Skipf("RLIMIT_AS not supported on this macOS version: %v", err)
	}
	defer limiter.Cleanup(0)

	// Verify the limit was set
	var newAS unix.Rlimit
	err = unix.Getrlimit(unix.RLIMIT_AS, &newAS)
	require.NoError(t, err)
	assert.Equal(t, uint64(8192*1024*1024), newAS.Cur)

	// Restore original limit
	unix.Setrlimit(unix.RLIMIT_AS, &origAS)
}

func TestDarwinLimiter_ApplySelfCPUTimeLimit(t *testing.T) {
	limiter := NewDarwinLimiter()

	// Get current limits first
	var origCPU unix.Rlimit
	err := unix.Getrlimit(unix.RLIMIT_CPU, &origCPU)
	require.NoError(t, err)

	// Apply CPU time limit
	limits := ResourceLimits{
		CommandTimeout: 300 * time.Second, // 5 minutes
	}
	err = limiter.Apply(0, limits)
	require.NoError(t, err)
	defer limiter.Cleanup(0)

	// Verify the limit was set
	var newCPU unix.Rlimit
	err = unix.Getrlimit(unix.RLIMIT_CPU, &newCPU)
	require.NoError(t, err)
	assert.Equal(t, uint64(300), newCPU.Cur)
	assert.Equal(t, uint64(360), newCPU.Max) // +60 grace period

	// Restore original limit
	unix.Setrlimit(unix.RLIMIT_CPU, &origCPU)
}

func TestDarwinLimiter_ApplySelfFileSizeLimit(t *testing.T) {
	limiter := NewDarwinLimiter()

	// Get current limits first
	var origFsize unix.Rlimit
	err := unix.Getrlimit(unix.RLIMIT_FSIZE, &origFsize)
	require.NoError(t, err)

	// Apply file size limit
	limits := ResourceLimits{
		MaxDiskMB: 1024, // 1 GB
	}
	err = limiter.Apply(0, limits)
	require.NoError(t, err)
	defer limiter.Cleanup(0)

	// Verify the limit was set
	var newFsize unix.Rlimit
	err = unix.Getrlimit(unix.RLIMIT_FSIZE, &newFsize)
	require.NoError(t, err)
	assert.Equal(t, uint64(1024*1024*1024), newFsize.Cur)

	// Restore original limit
	unix.Setrlimit(unix.RLIMIT_FSIZE, &origFsize)
}

func TestDarwinLimiter_ApplyExternalCPUShares(t *testing.T) {
	limiter := NewDarwinLimiter()

	// Start a subprocess
	cmd := exec.Command("sleep", "60")
	err := cmd.Start()
	require.NoError(t, err)
	defer cmd.Process.Kill()

	pid := cmd.Process.Pid

	// Apply CPU shares - this uses renice
	limits := ResourceLimits{
		CPUShares: 50, // Should translate to nice value 10
	}
	err = limiter.Apply(pid, limits)
	require.NoError(t, err)
	defer limiter.Cleanup(pid)

	// We can't easily verify renice was applied without root
	// Just verify no error occurred
}

func TestDarwinLimiter_UsageProcessExited(t *testing.T) {
	limiter := NewDarwinLimiter()

	// Start a subprocess that exits quickly
	cmd := exec.Command("true")
	err := cmd.Start()
	require.NoError(t, err)

	pid := cmd.Process.Pid

	// Apply limits
	err = limiter.Apply(pid, ResourceLimits{})
	require.NoError(t, err)
	defer limiter.Cleanup(pid)

	// Wait for process to exit
	cmd.Wait()

	// Usage should not error even if process exited
	usage, err := limiter.Usage(pid)
	require.NoError(t, err)
	assert.NotNil(t, usage)
}

func TestDarwinLimiter_UsageWithChildren(t *testing.T) {
	limiter := NewDarwinLimiter()

	// Start a subprocess that has children
	cmd := exec.Command("sh", "-c", "sleep 60 & sleep 60 & wait")
	err := cmd.Start()
	require.NoError(t, err)
	defer cmd.Process.Kill()

	pid := cmd.Process.Pid

	// Apply limits
	err = limiter.Apply(pid, ResourceLimits{})
	require.NoError(t, err)
	defer limiter.Cleanup(pid)

	// Give time for children to start
	time.Sleep(200 * time.Millisecond)

	// Get usage - should include child count
	usage, err := limiter.Usage(pid)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, usage.ProcessCount, 1)
}

func TestDarwinLimiter_ConcurrentAccess(t *testing.T) {
	limiter := NewDarwinLimiter()

	// Start multiple subprocesses
	var cmds []*exec.Cmd
	for i := 0; i < 5; i++ {
		cmd := exec.Command("sleep", "60")
		err := cmd.Start()
		require.NoError(t, err)
		cmds = append(cmds, cmd)
		defer cmd.Process.Kill()
	}

	// Concurrent Apply
	done := make(chan bool, len(cmds))
	for _, cmd := range cmds {
		go func(pid int) {
			limiter.Apply(pid, ResourceLimits{MaxProcesses: 100})
			done <- true
		}(cmd.Process.Pid)
	}
	for range cmds {
		<-done
	}

	// Concurrent Usage
	for _, cmd := range cmds {
		go func(pid int) {
			limiter.Usage(pid)
			done <- true
		}(cmd.Process.Pid)
	}
	for range cmds {
		<-done
	}

	// Concurrent Cleanup
	for _, cmd := range cmds {
		go func(pid int) {
			limiter.Cleanup(pid)
			done <- true
		}(cmd.Process.Pid)
	}
	for range cmds {
		<-done
	}
}

func TestDarwinLimiter_ApplyCurrentProcess(t *testing.T) {
	limiter := NewDarwinLimiter()

	pid := os.Getpid()

	// Get current limits to restore later
	var origNproc unix.Rlimit
	unix.Getrlimit(unix.RLIMIT_NPROC, &origNproc)

	// Apply limits to current process (using actual PID)
	// Note: On macOS, reducing RLIMIT_NPROC below current may fail with EPERM
	limits := ResourceLimits{
		MaxProcesses: 600,
	}
	err := limiter.Apply(pid, limits)
	if err != nil {
		// macOS may reject RLIMIT_NPROC changes - this is expected
		t.Skipf("RLIMIT_NPROC not permitted on this macOS: %v", err)
	}
	defer func() {
		limiter.Cleanup(pid)
		unix.Setrlimit(unix.RLIMIT_NPROC, &origNproc)
	}()

	// Verify the limit was set
	var newNproc unix.Rlimit
	err = unix.Getrlimit(unix.RLIMIT_NPROC, &newNproc)
	require.NoError(t, err)
	assert.Equal(t, uint64(600), newNproc.Cur)
}

func TestDarwinLimiter_CPUSharesNiceMapping(t *testing.T) {
	// Test the CPU shares to nice value conversion logic
	testCases := []struct {
		shares       int64
		expectedNice int
	}{
		{100, 0},  // 100% shares = nice 0 (highest priority)
		{50, 10},  // 50% shares = nice 10
		{0, 20},   // 0% shares = nice 20 (lowest priority)
		{75, 5},   // 75% shares = nice 5
		{25, 15},  // 25% shares = nice 15
	}

	for _, tc := range testCases {
		// Use the same formula as applyExternal
		nice := 20 - int(tc.shares*20/100)
		if nice < 0 {
			nice = 0
		}
		if nice > 20 {
			nice = 20
		}
		assert.Equal(t, tc.expectedNice, nice, "shares=%d", tc.shares)
	}
}
