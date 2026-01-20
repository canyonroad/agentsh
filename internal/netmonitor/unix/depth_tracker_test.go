// internal/netmonitor/unix/depth_tracker_test.go
package unix

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDepthTracker_RegisterSession(t *testing.T) {
	dt := NewDepthTracker()

	dt.RegisterSession(1000, "sess-123")

	state, ok := dt.Get(1000)
	assert.True(t, ok)
	// Session root is at depth -1 so first child will be at depth 0 (direct)
	assert.Equal(t, -1, state.Depth)
	assert.Equal(t, "sess-123", state.SessionID)
}

func TestDepthTracker_RecordExecve(t *testing.T) {
	dt := NewDepthTracker()
	dt.RegisterSession(1000, "sess-123") // depth -1

	// Child of session root - direct command at depth 0
	dt.RecordExecve(1001, 1000)

	state, ok := dt.Get(1001)
	assert.True(t, ok)
	assert.Equal(t, 0, state.Depth) // parent (-1) + 1 = 0
	assert.Equal(t, "sess-123", state.SessionID)

	// Grandchild - nested command at depth 1
	dt.RecordExecve(1002, 1001)

	state, ok = dt.Get(1002)
	assert.True(t, ok)
	assert.Equal(t, 1, state.Depth) // parent (0) + 1 = 1
}

func TestDepthTracker_Cleanup(t *testing.T) {
	dt := NewDepthTracker()
	dt.RegisterSession(1000, "sess-123")
	dt.RecordExecve(1001, 1000)

	dt.Cleanup(1001)

	_, ok := dt.Get(1001)
	assert.False(t, ok)

	// Parent should still exist
	_, ok = dt.Get(1000)
	assert.True(t, ok)
}

func TestDepthTracker_UnknownParent(t *testing.T) {
	dt := NewDepthTracker()

	// Recording for unknown parent should still work (depth 0)
	dt.RecordExecve(1001, 9999)

	state, ok := dt.Get(1001)
	assert.True(t, ok)
	assert.Equal(t, 0, state.Depth)
	assert.Equal(t, "", state.SessionID)
}
