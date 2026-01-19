package ancestry

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCaptureSnapshot_CurrentProcess(t *testing.T) {
	pid := os.Getpid()
	snapshot, err := CaptureSnapshot(pid)

	require.NoError(t, err)
	require.NotNil(t, snapshot)

	// Comm should be set (the test binary name)
	assert.NotEmpty(t, snapshot.Comm)

	// StartTime should be non-zero
	assert.NotZero(t, snapshot.StartTime)

	t.Logf("Snapshot of current process (PID %d): Comm=%s, ExePath=%s, StartTime=%d",
		pid, snapshot.Comm, snapshot.ExePath, snapshot.StartTime)
}

func TestCaptureSnapshot_NonExistentProcess(t *testing.T) {
	// Use a very high PID that's unlikely to exist
	pid := 999999999
	_, err := CaptureSnapshot(pid)

	// Should return an error
	assert.Error(t, err)
}

func TestValidateSnapshot_Valid(t *testing.T) {
	pid := os.Getpid()

	// Capture snapshot of current process
	snapshot, err := CaptureSnapshot(pid)
	require.NoError(t, err)

	// Validate should return true (same process)
	valid := ValidateSnapshot(pid, snapshot)
	assert.True(t, valid)
}

func TestValidateSnapshot_NilSnapshot(t *testing.T) {
	pid := os.Getpid()
	valid := ValidateSnapshot(pid, nil)
	assert.False(t, valid)
}

func TestValidateSnapshot_ProcessExited(t *testing.T) {
	// Create a snapshot with a fake start time
	snapshot := &ProcessSnapshot{
		Comm:      "fake",
		StartTime: 12345,
	}

	// Validate against a non-existent PID should return true
	// (we can't validate, so we trust the cached data)
	valid := ValidateSnapshot(999999999, snapshot)
	assert.True(t, valid)
}

func TestValidateSnapshot_DifferentStartTime(t *testing.T) {
	pid := os.Getpid()

	// Create a snapshot with wrong start time
	snapshot := &ProcessSnapshot{
		Comm:      "fake",
		StartTime: 1, // Wrong start time
	}

	// Validate should return false (different process based on start time)
	valid := ValidateSnapshot(pid, snapshot)
	assert.False(t, valid)
}

func TestCaptureSnapshot_Consistency(t *testing.T) {
	pid := os.Getpid()

	// Capture two snapshots of the same process
	snapshot1, err := CaptureSnapshot(pid)
	require.NoError(t, err)

	snapshot2, err := CaptureSnapshot(pid)
	require.NoError(t, err)

	// StartTime should be the same (process hasn't restarted)
	assert.Equal(t, snapshot1.StartTime, snapshot2.StartTime)

	// Comm should be the same
	assert.Equal(t, snapshot1.Comm, snapshot2.Comm)
}
