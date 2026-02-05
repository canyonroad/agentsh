//go:build darwin

package process

import (
	"context"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDarwinProcessTracker_NewPlatformTracker(t *testing.T) {
	tracker := newPlatformTracker()
	require.NotNil(t, tracker)

	dt, ok := tracker.(*DarwinProcessTracker)
	require.True(t, ok, "expected *DarwinProcessTracker")
	assert.NotNil(t, dt.known)
	assert.NotNil(t, dt.done)
}

func TestDarwinProcessTracker_Capabilities(t *testing.T) {
	tracker := newPlatformTracker().(*DarwinProcessTracker)
	caps := tracker.Capabilities()

	assert.False(t, caps.AutoChildTracking, "darwin uses polling, not auto-tracking")
	assert.True(t, caps.SpawnNotification)
	assert.True(t, caps.ExitNotification)
	assert.False(t, caps.ExitCodes, "darwin tracker doesn't capture exit codes")
}

func TestDarwinProcessTracker_TrackSelf(t *testing.T) {
	tracker := newPlatformTracker().(*DarwinProcessTracker)
	defer tracker.Stop()

	pid := os.Getpid()
	err := tracker.Track(pid)
	require.NoError(t, err)

	assert.Equal(t, pid, tracker.rootPID)
	assert.True(t, tracker.Contains(pid))

	pids := tracker.ListPIDs()
	assert.Contains(t, pids, pid)
}

func TestDarwinProcessTracker_ContainsUntracked(t *testing.T) {
	tracker := newPlatformTracker().(*DarwinProcessTracker)
	defer tracker.Stop()

	// Track ourselves
	err := tracker.Track(os.Getpid())
	require.NoError(t, err)

	// PID 1 (launchd) should not be in our tree
	assert.False(t, tracker.Contains(1))
}

func TestDarwinProcessTracker_InfoSelf(t *testing.T) {
	tracker := newPlatformTracker().(*DarwinProcessTracker)
	defer tracker.Stop()

	pid := os.Getpid()
	err := tracker.Track(pid)
	require.NoError(t, err)

	info, err := tracker.Info(pid)
	require.NoError(t, err)
	assert.Equal(t, pid, info.PID)
	assert.NotZero(t, info.PPID)
	// Command should contain the test binary name
	assert.NotEmpty(t, info.Command)
}

func TestDarwinProcessTracker_InfoUntracked(t *testing.T) {
	tracker := newPlatformTracker().(*DarwinProcessTracker)
	defer tracker.Stop()

	err := tracker.Track(os.Getpid())
	require.NoError(t, err)

	// Try to get info for a PID not in our tree
	_, err = tracker.Info(1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not tracked")
}

func TestDarwinProcessTracker_DetectsChildProcess(t *testing.T) {
	tracker := newPlatformTracker().(*DarwinProcessTracker)
	defer tracker.Stop()

	pid := os.Getpid()
	err := tracker.Track(pid)
	require.NoError(t, err)

	var spawnedPID int
	var spawnedPPID int
	var mu sync.Mutex
	spawned := make(chan struct{}, 1)

	tracker.OnSpawn(func(childPID, parentPID int) {
		mu.Lock()
		spawnedPID = childPID
		spawnedPPID = parentPID
		mu.Unlock()
		select {
		case spawned <- struct{}{}:
		default:
		}
	})

	// Start a child process that sleeps
	cmd := exec.Command("sleep", "5")
	err = cmd.Start()
	require.NoError(t, err)
	defer cmd.Process.Kill()

	childPID := cmd.Process.Pid

	// Wait for the tracker to detect the child (polling interval is 100ms)
	select {
	case <-spawned:
		// Child detected
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for spawn detection")
	}

	mu.Lock()
	assert.Equal(t, childPID, spawnedPID)
	assert.Equal(t, pid, spawnedPPID)
	mu.Unlock()

	assert.True(t, tracker.Contains(childPID))
}

func TestDarwinProcessTracker_DetectsChildExit(t *testing.T) {
	tracker := newPlatformTracker().(*DarwinProcessTracker)
	defer tracker.Stop()

	pid := os.Getpid()
	err := tracker.Track(pid)
	require.NoError(t, err)

	// Start a child process first so we know its PID
	cmd := exec.Command("sleep", "10")
	err = cmd.Start()
	require.NoError(t, err)

	childPID := cmd.Process.Pid

	var exitedPID int
	var mu sync.Mutex
	exited := make(chan struct{}, 1)
	spawned := make(chan struct{}, 1)

	// Only signal when OUR child spawns/exits, not random system processes
	tracker.OnSpawn(func(spawnedPID, parentPID int) {
		if spawnedPID == childPID {
			select {
			case spawned <- struct{}{}:
			default:
			}
		}
	})

	tracker.OnExit(func(exitPID, exitCode int) {
		if exitPID == childPID {
			mu.Lock()
			exitedPID = exitPID
			mu.Unlock()
			select {
			case exited <- struct{}{}:
			default:
			}
		}
	})

	// Wait for spawn detection first
	select {
	case <-spawned:
		// Child detected
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for spawn detection")
	}

	// Now kill the child
	cmd.Process.Kill()
	cmd.Wait()

	// Wait for the tracker to detect the exit
	select {
	case <-exited:
		mu.Lock()
		assert.Equal(t, childPID, exitedPID)
		mu.Unlock()
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for exit detection")
	}

	// After exit, should no longer be in the tree
	assert.False(t, tracker.Contains(childPID))
}

func TestDarwinProcessTracker_KillAll(t *testing.T) {
	tracker := newPlatformTracker().(*DarwinProcessTracker)
	defer tracker.Stop()

	// Start a child process first
	cmd := exec.Command("sleep", "60")
	err := cmd.Start()
	require.NoError(t, err)

	childPID := cmd.Process.Pid
	defer cmd.Process.Kill() // cleanup in case test fails

	// Track the child process (not ourselves to avoid killing the test)
	err = tracker.Track(childPID)
	require.NoError(t, err)

	assert.True(t, tracker.Contains(childPID))

	// Kill all with SIGTERM
	err = tracker.KillAll(syscall.SIGTERM)
	require.NoError(t, err)

	// Child should exit
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-done:
		// Child exited as expected
	case <-time.After(2 * time.Second):
		t.Fatal("child process did not exit after KillAll")
	}
}

func TestDarwinProcessTracker_Wait(t *testing.T) {
	tracker := newPlatformTracker().(*DarwinProcessTracker)
	defer tracker.Stop()

	// Start a quick subprocess using 'true' which exits immediately
	cmd := exec.Command("true")
	err := cmd.Start()
	require.NoError(t, err)

	childPID := cmd.Process.Pid

	// Wait for the command to actually exit first
	cmd.Wait()

	// Track the child directly - it's already exited
	err = tracker.Track(childPID)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Wait should return quickly since process already exited
	err = tracker.Wait(ctx)
	assert.NoError(t, err)
}

func TestDarwinProcessTracker_WaitContextCancelled(t *testing.T) {
	tracker := newPlatformTracker().(*DarwinProcessTracker)
	defer tracker.Stop()

	// Start a long-running subprocess
	cmd := exec.Command("sleep", "60")
	err := cmd.Start()
	require.NoError(t, err)
	defer cmd.Process.Kill()

	childPID := cmd.Process.Pid

	err = tracker.Track(childPID)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Wait should return context error
	err = tracker.Wait(ctx)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestDarwinProcessTracker_Stop(t *testing.T) {
	tracker := newPlatformTracker().(*DarwinProcessTracker)

	err := tracker.Track(os.Getpid())
	require.NoError(t, err)

	// Verify polling is running by checking a child can be detected
	cmd := exec.Command("sleep", "5")
	err = cmd.Start()
	require.NoError(t, err)
	defer cmd.Process.Kill()

	// Give time for at least one poll cycle
	time.Sleep(150 * time.Millisecond)

	// Stop should not error
	err = tracker.Stop()
	assert.NoError(t, err)

	// After stop, done channel should be closed
	select {
	case <-tracker.done:
		// Expected - channel closed
	default:
		t.Error("done channel should be closed after Stop()")
	}
}

func TestDarwinProcessTracker_GetChildren(t *testing.T) {
	tracker := newPlatformTracker().(*DarwinProcessTracker)
	defer tracker.Stop()

	pid := os.Getpid()

	// Start a child
	cmd := exec.Command("sleep", "5")
	err := cmd.Start()
	require.NoError(t, err)
	defer cmd.Process.Kill()

	childPID := cmd.Process.Pid

	// getChildren should find our child
	children := tracker.getChildren(pid)
	assert.Contains(t, children, childPID)
}

func TestDarwinProcessTracker_GetPPID(t *testing.T) {
	tracker := newPlatformTracker().(*DarwinProcessTracker)

	ppid := tracker.getPPID(os.Getpid())
	assert.Equal(t, os.Getppid(), ppid)
}

func TestDarwinProcessTracker_ProcessExists(t *testing.T) {
	tracker := newPlatformTracker().(*DarwinProcessTracker)

	// Current process exists
	assert.True(t, tracker.processExists(os.Getpid()))

	// Parent process should exist
	assert.True(t, tracker.processExists(os.Getppid()))

	// Very high PID probably doesn't exist
	assert.False(t, tracker.processExists(999999999))

	// Start a process, kill it, verify it doesn't exist
	cmd := exec.Command("sleep", "60")
	err := cmd.Start()
	require.NoError(t, err)
	pid := cmd.Process.Pid
	assert.True(t, tracker.processExists(pid))
	cmd.Process.Kill()
	cmd.Wait()
	// Small delay for OS to clean up
	time.Sleep(10 * time.Millisecond)
	assert.False(t, tracker.processExists(pid))
}

func TestDarwinProcessTracker_ListPIDsConcurrent(t *testing.T) {
	tracker := newPlatformTracker().(*DarwinProcessTracker)
	defer tracker.Stop()

	err := tracker.Track(os.Getpid())
	require.NoError(t, err)

	// Concurrent access should be safe
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = tracker.ListPIDs()
				_ = tracker.Contains(os.Getpid())
			}
		}()
	}
	wg.Wait()
}

func TestDarwinProcessTracker_NilCallbacks(t *testing.T) {
	tracker := newPlatformTracker().(*DarwinProcessTracker)
	defer tracker.Stop()

	// Don't set any callbacks
	err := tracker.Track(os.Getpid())
	require.NoError(t, err)

	// Start and quickly exit a child
	cmd := exec.Command("true")
	err = cmd.Start()
	require.NoError(t, err)
	cmd.Wait()

	// Let polling run - should not panic with nil callbacks
	time.Sleep(200 * time.Millisecond)
}

func TestDarwinProcessTracker_KillAllWithNilSignal(t *testing.T) {
	tracker := newPlatformTracker().(*DarwinProcessTracker)
	defer tracker.Stop()

	// Start a child process first
	cmd := exec.Command("sleep", "60")
	err := cmd.Start()
	require.NoError(t, err)
	defer cmd.Process.Kill()

	// Track the child process (not ourselves to avoid killing the test)
	err = tracker.Track(cmd.Process.Pid)
	require.NoError(t, err)

	assert.True(t, tracker.Contains(cmd.Process.Pid))

	// Pass a non-unix.Signal type - should default to SIGTERM
	err = tracker.KillAll(nil)
	require.NoError(t, err)

	// Child should exit
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-done:
		// Expected
	case <-time.After(2 * time.Second):
		t.Fatal("child did not exit after KillAll(nil)")
	}
}

func TestDarwinProcessTracker_GrandchildDetection(t *testing.T) {
	tracker := newPlatformTracker().(*DarwinProcessTracker)
	defer tracker.Stop()

	// Start a shell that spawns grandchildren
	cmd := exec.Command("sh", "-c", "sleep 5 & sleep 5")
	err := cmd.Start()
	require.NoError(t, err)
	defer cmd.Process.Kill()

	// Track the shell process (not ourselves)
	err = tracker.Track(cmd.Process.Pid)
	require.NoError(t, err)

	spawnCount := 0
	var mu sync.Mutex

	tracker.OnSpawn(func(pid, ppid int) {
		mu.Lock()
		spawnCount++
		mu.Unlock()
	})

	// Wait for detection of grandchildren (the two sleep processes)
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return spawnCount >= 2
	}, time.Second, 100*time.Millisecond, "should detect at least 2 grandchild spawns")

	// Kill everything
	tracker.KillAll(syscall.SIGKILL)
	cmd.Wait()
}
